//! TeleAgent（星辰超级智能体）请求签名：**两层 HMAC-SHA256**。
//!
//! ── 算法（逐字对拍参考实现 `T786279007/teleagent2api-deploy` 的 `internal/proxy/proxy.go`）──
//! ```text
//!   derivedKey    = hex(HMAC_SHA256(key = JWT 第三段,
//!                                   msg = "superagent-auth-v1/{token}/{installId}/{ts}/{nonce}"))
//!   bodySHA       = sha256hex(body)
//!   requestString = "superagent-auth-v1\n{POST}\n{pathWithQuery}\n{ts}\n{nonce}\n{appVersion}\n{bodySHA}"
//!   signature     = hex(HMAC_SHA256(key = derivedKey 的 **ASCII 字节**（不是十六进制解码后的 32 字节）,
//!                                   msg = requestString))
//! ```
//!
//! ── 两个最容易做错的点 ────────────────────────────────────────
//! 1. **第二层 HMAC 的 key 是第一次的十六进制串，不是它解码出来的字节。**
//!    参考实现把 `hmacSHA256Hex` 的返回值（`string`）直接当 key 传回去，Go 里
//!    `[]byte(hex 串)` 就是那 64 个 ASCII 字符。换成解码后的 32 字节会**签名全错**，
//!    且上游只回一个笼统的签名失败，看不出差在哪。
//! 2. **`derivedKey` 的 key 是 JWT 的第三段原文**（base64url 的签名字符串），
//!    不是 base64 解码后的字节，也不是整个 token。
//!
//! ── 时间戳单位是**秒** ─────────────────────────────────────
//! 参考实现用 `time.Now().Unix()`（秒）。用毫秒会让上游算出的时间窗偏移三个数量级。

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// 签名前缀（同时出现在 `derivedKey` 的 msg 与 `requestString` 的第一行）
pub const SIGN_PREFIX: &str = "superagent-auth-v1";
/// 签名版本头 `X-SuperAgent-Sign-Version` 的取值
pub const SIGN_VERSION: &str = "v1";

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度的密钥");
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `sha256hex`（小写十六进制）
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 取 JWT 的第三段（签名段）。
///
/// 上游的 `token` 是标准 JWT；拿不到三段就说明用户粘错了东西 —— 这时**必须报错**，
/// 不能退化成「用整个 token 当 key」，那只会换来一个上游签名失败的笼统提示。
pub fn jwt_third_segment(token: &str) -> Result<&str, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[2].trim().is_empty() {
        return Err(
            "TeleAgent 登录态不是有效的 JWT（应为三段点分）。请在 TeleAgent 客户端里重新获取 token"
                .to_string(),
        );
    }
    Ok(parts[2])
}

/// 第一层：由 token / installId / 时间戳 / nonce 派生签名密钥。
pub fn derived_key(token: &str, install_id: &str, timestamp: &str, nonce: &str) -> Result<String, String> {
    let third = jwt_third_segment(token)?;
    let basic = format!("{SIGN_PREFIX}/{token}/{install_id}/{timestamp}/{nonce}");
    Ok(hmac_sha256_hex(third.as_bytes(), &basic))
}

/// 待签字符串（`\n` 连接七行）。
pub fn request_string(
    path_with_query: &str,
    timestamp: &str,
    nonce: &str,
    app_version: &str,
    body_sha: &str,
) -> String {
    [
        SIGN_PREFIX,
        "POST",
        path_with_query,
        timestamp,
        nonce,
        app_version,
        body_sha,
    ]
    .join("\n")
}

/// 第二层：真正的签名。
///
/// ⚠️ `derived_key` 是**十六进制字符串**，用它本身的 ASCII 字节当 HMAC key
/// （见模块头第 1 条）。
pub fn signature(key_hex: &str, request: &str) -> String {
    hmac_sha256_hex(key_hex.as_bytes(), request)
}

/// 一次性算出全套签名材料。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    pub timestamp: String,
    pub nonce: String,
    pub derived_key: String,
    pub body_sha: String,
    pub request_string: String,
    pub signature: String,
}

/// 给一次请求签名。
pub fn sign(
    token: &str,
    install_id: &str,
    timestamp: &str,
    nonce: &str,
    app_version: &str,
    path_with_query: &str,
    body: &[u8],
) -> Result<SignedRequest, String> {
    let derived_key = derived_key(token, install_id, timestamp, nonce)?;
    let body_sha = sha256_hex(body);
    let request_string = request_string(path_with_query, timestamp, nonce, app_version, &body_sha);
    let signature = signature(&derived_key, &request_string);
    Ok(SignedRequest {
        timestamp: timestamp.to_string(),
        nonce: nonce.to_string(),
        derived_key,
        body_sha,
        request_string,
        signature,
    })
}

/// 生成一个 UUID v4 形态的 nonce（8-4-4-4-12 小写十六进制）。
///
/// 参考实现用 UUID 当 nonce；上游只要求它每次不同，形态上跟住即可。
pub fn new_nonce() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// 生成 `msg_` / `ses_` 那种 32 位十六进制 id。
pub fn new_hex_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 钉住算法本身。
    ///
    /// 期望值由**独立实现**（Python，照抄参考实现的 Go 逻辑）算出，
    /// 不是从本文件反推的 —— 这样才挡得住「两层 HMAC 里哪一层用错了 key」。
    #[test]
    fn the_two_layer_signature_matches_an_independently_computed_vector() {
        let signed = sign(
            "aaa.bbb.ccc",
            "install-123",
            "1700000000",
            "11111111-2222-3333-4444-555555555555",
            "2.0.0",
            "/superCowork/sapi/api/v1/chat/completions",
            br#"{"model":"chat-pro"}"#,
        )
        .expect("签名应当成功");

        assert_eq!(signed.derived_key, "fc4dd5872ad5c8fab95a121a6dd4df4c74ba20f8d44b4170bd1793a206d6a291");
        assert_eq!(signed.body_sha, "51c7c91721a45b24be9f1e000006da7d3be4294b24434207b2cce64a47d74ff0");
        assert_eq!(
            signed.request_string,
            "superagent-auth-v1\nPOST\n/superCowork/sapi/api/v1/chat/completions\n1700000000\n\
             11111111-2222-3333-4444-555555555555\n2.0.0\n\
             51c7c91721a45b24be9f1e000006da7d3be4294b24434207b2cce64a47d74ff0"
        );
        assert_eq!(signed.signature, "e21fcfbf3f55a0e03022ab33566976aa354105ae97c73c7413e84da84cd3dd44");
    }

    /// ⚠️ 第二层的 key 必须是**十六进制串的 ASCII 字节**，不是解码后的 32 字节。
    /// 这条用例把两种写法都算出来，钉住「我们用的是前者」。
    #[test]
    fn the_second_layer_uses_the_hex_string_not_its_decoded_bytes() {
        let request = "superagent-auth-v1\nPOST\n/p\n1\nn\n2.0.0\nabc";
        let key_hex = "fc4dd5872ad5c8fab95a121a6dd4df4c74ba20f8d44b4170bd1793a206d6a291";
        let correct = signature(key_hex, request);

        // 错误写法：把 hex 解码成 32 字节再当 key
        let mut decoded = Vec::with_capacity(32);
        for index in (0..key_hex.len()).step_by(2) {
            decoded.push(u8::from_str_radix(&key_hex[index..index + 2], 16).unwrap());
        }
        let wrong = hmac_sha256_hex(&decoded, request);

        assert_ne!(correct, wrong, "两种 key 写法必须算出不同签名，否则这条用例挡不住什么");
        assert_eq!(correct.len(), 64);
        assert!(correct.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    /// JWT 段数不对必须报错，不能退化成「拿整个 token 当 key」。
    #[test]
    fn a_non_jwt_token_is_rejected() {
        assert!(jwt_third_segment("not-a-jwt").is_err());
        assert!(jwt_third_segment("a.b").is_err());
        assert!(jwt_third_segment("a.b.").is_err());
        assert_eq!(jwt_third_segment("a.b.c").unwrap(), "c");
    }

    /// nonce 每次不同、形态是 UUID v4。
    #[test]
    fn a_nonce_is_a_fresh_uuid() {
        let first = new_nonce();
        let second = new_nonce();
        assert_ne!(first, second);
        assert_eq!(first.len(), 36);
        let groups: Vec<&str> = first.split('-').collect();
        assert_eq!(groups.iter().map(|g| g.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
        assert!(first.chars().filter(|ch| *ch != '-').all(|ch| ch.is_ascii_hexdigit()));
    }

    /// 十六进制 id 是 32 位小写 hex。
    #[test]
    fn a_hex_id_is_thirty_two_lowercase_chars() {
        let id = new_hex_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }
}
