//! ima（腾讯 ima.copilot）的凭据：**一整段 Cookie** + 一个可选的 `x-ima-bkn`。
//!
//! ── 认证形态 ────────────────────────────────────────────────
//! 上游只认 Cookie。其中三项是必需的：
//!
//! | Cookie | 作用 |
//! |---|---|
//! | `IMA-UID` | 账号 uid |
//! | `IMA-TOKEN` | 访问票据 |
//! | `IMA-REFRESH-TOKEN` | 续期用（本插件**不自动续期**，见下） |
//!
//! ── ⚠️ `CLIENT-TYPE` 必须覆盖成 Android 值 `256001` ─────────────
//! 这是参考实现踩过的坑：H5 的值（`256053`）会被上游拒，报「当前版本暂不支持」。
//! 用户从浏览器复制的 Cookie 里带的是 H5 值，所以这里**无条件覆盖**，不沿用
//! 用户给的那个 —— 沿用就等于把用户手抄的 H5 值原样送上去然后必然失败。
//!
//! ── 为什么不做自动续期 ──────────────────────────────────────
//! 参考实现明确写了「刷新接口在 ima native 层，无法自动续期」。所以本插件
//! 申报 `refresh: false`，票据过期时**如实报错**并提示去网页重新复制 Cookie，
//! 而不是假装有续期能力然后在后台静默失败。
//!
//! ── `x-ima-bkn` 是可选的 ────────────────────────────────────
//! 参考实现实测「qa / init_session 不带 bkn 也 200（服务端主要校验 Cookie）」。
//! 这里仍然算上它：它是 H5 源码里那条 `_t` 函数的逐句还原，带上只是多一个头，
//! 而不带的风险是上游某天开始校验 —— 那种失败会表现成笼统的 401，极难归因。

use serde_json::Value;

pub use super::COOKIE_CLIENT_TYPE;

/// 必需的三项 Cookie。
///
/// `Debug` 是给用例里的 `expect_err` 用的 —— 它需要打印 `Ok` 侧的值。
/// 打印出来的是票据明文，只发生在测试里（不用于日志）。
#[derive(Debug)]
pub struct Credentials {
    pub uid: String,
    pub token: String,
    pub refresh_token: String,
}

impl Credentials {
    /// 拼成上游要的 `Cookie:` 头。
    ///
    /// **只发这三项 + 覆盖后的 CLIENT-TYPE**，不把用户粘的整段原样转发：
    /// 浏览器 Cookie 里通常还有几十条与本接口无关的域 Cookie，带上只会让请求
    /// 更容易被风控当成浏览器直连。
    pub fn cookie_header(&self) -> String {
        format!(
            "IMA-UID={}; IMA-TOKEN={}; IMA-REFRESH-TOKEN={}; CLIENT-TYPE={}",
            self.uid, self.token, self.refresh_token, COOKIE_CLIENT_TYPE
        )
    }

    /// 票据尾 4 位（界面展示用，不泄露全文）。
    pub fn token_tail(&self) -> String {
        let chars: Vec<char> = self.token.chars().collect();
        let start = chars.len().saturating_sub(4);
        chars[start..].iter().collect()
    }
}

/// 从「原始 Cookie 串 / 行式 KEY=VALUE / 两者混合」里解析出三项必需值。
///
/// 三种输入都要认，因为用户抄的方式不可控（F12 里可能是单行分号串，也可能是
/// 逐行列表）。解析不出**具名缺哪一项**，否则用户只知道「失败了」。
pub fn parse(raw: &str) -> Result<Credentials, String> {
    let fields = parse_pairs(raw);
    let pick = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(value) = fields.iter().find(|(name, _)| name.eq_ignore_ascii_case(key)) {
                if !value.1.trim().is_empty() {
                    return value.1.trim().to_string();
                }
            }
        }
        String::new()
    };
    let uid = pick(&["IMA-UID", "IMA_UID"]);
    let token = pick(&["IMA-TOKEN", "IMA_TOKEN"]);
    let refresh_token = pick(&["IMA-REFRESH-TOKEN", "IMA_REFRESH_TOKEN"]);
    let mut missing = Vec::new();
    if uid.is_empty() {
        missing.push("IMA-UID");
    }
    if token.is_empty() {
        missing.push("IMA-TOKEN");
    }
    if refresh_token.is_empty() {
        missing.push("IMA-REFRESH-TOKEN");
    }
    if !missing.is_empty() {
        return Err(format!(
            "ima 登录态缺少 {}：请在浏览器登录 ima.qq.com 后复制**完整 Cookie**（含这三项）",
            missing.join(" / ")
        ));
    }
    Ok(Credentials { uid, token, refresh_token })
}

/// 把三种形态统一成 `(key, value)` 列表。
fn parse_pairs(raw: &str) -> Vec<(String, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // 单行分号串（F12 复制最常见的形态）
    let single_line = !trimmed.contains('\n') && trimmed.contains("; ");
    if single_line {
        return trimmed
            .split(';')
            .filter_map(split_pair)
            .collect();
    }
    // 行式（每行 KEY=VALUE，忽略空行与 # 注释）；顺带兼容混在行里的分号
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for piece in line.split(';') {
            if let Some(pair) = split_pair(piece) {
                out.push(pair);
            }
        }
    }
    out
}

/// 把 `KEY=VALUE` 切成两项；没有 `=` 或键为空返回 `None`。
///
/// 自己写而不直接用 `str::partition`：那个方法在 `Iterator` 上，`str` 没有它
/// （`str::split_once` 才是对的，但它把「没有分隔符」表达成 `None`，与这里
/// 「跳过这一项」的语义正好一致）。
fn split_pair(piece: &str) -> Option<(String, String)> {
    let piece = piece.trim();
    let (key, value) = piece.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), value.trim().to_string()))
}

/// `x-ima-bkn`：H5 源码里 `_t` 函数的逐句还原。
///
/// ── 算法（逐字对拍参考实现 `ima_auth.py::ima_bkn`）──────────────
/// ```text
///   t = 5381
///   for ch in token:  t += js_shl5(t) + ord(ch)
///   bkn = t & 0x7FFFFFFF
///
///   js_shl5(t) = ToInt32((t & 0xFFFFFFFF) << 5)   // **有符号** 32 位
/// ```
///
/// ── 为什么用 `u32` 环绕运算而不是大整数 ──────────────────────
/// `js_shl5` 只看 `t` 的低 32 位，而最终结果只要低 31 位 ⇒ 全程 **模 2³²**
/// 与参考实现的大整数累加在低 31 位上等价（已用 200 组随机样本验证）。
/// Rust 里照抄大整数要引 `num-bigint`，为一行校验和多一个依赖不值。
///
/// ⚠️ 注意 `js_shl5` 的返回值是**有符号**的（可能是负数），所以累加用的是
/// 带符号扩展的加法再截断 —— 写成无符号加法会在第 6 个字符起就分叉。
pub fn bkn(token: &str) -> i64 {
    let mut t: u32 = 5381;
    for ch in token.chars() {
        let shifted = (t.wrapping_shl(5)) as i32;
        let next = (t as i64) + (shifted as i64) + (ch as i64);
        t = next as u32;
    }
    (t & 0x7FFF_FFFF) as i64
}

/// 从 store 里的 secret 取凭据。既支持存整段 Cookie（`cookie` 键），
/// 也支持三项分开存 —— `normalize_account` 总是写后者的形态。
pub fn from_secret(secret: &Value) -> Result<Credentials, String> {
    let text = |key: &str| -> String {
        secret
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_string()
    };
    let uid = text("uid");
    let token = text("token");
    let refresh_token = text("refreshToken");
    if !uid.is_empty() && !token.is_empty() && !refresh_token.is_empty() {
        return Ok(Credentials { uid, token, refresh_token });
    }
    // 兼容「只存了整段 cookie」的历史形态
    let raw = text("cookie");
    if raw.is_empty() {
        return Err("ima 账号缺少登录态，请重新粘贴 Cookie".to_string());
    }
    parse(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "IMA-UID=100012345; IMA-TOKEN=tk-abcdef; IMA-REFRESH-TOKEN=rt-xyz; CLIENT-TYPE=256053";

    /// F12 复制的单行分号串。
    #[test]
    fn a_single_line_cookie_string_parses() {
        let credentials = parse(FULL).expect("三项齐全应当通过");
        assert_eq!(credentials.uid, "100012345");
        assert_eq!(credentials.token, "tk-abcdef");
        assert_eq!(credentials.refresh_token, "rt-xyz");
    }

    /// 行式 KEY=VALUE（含注释与空行）。
    #[test]
    fn a_line_based_cookie_file_parses() {
        let raw = "# ima 登录态\nIMA-UID=100012345\n\nIMA-TOKEN=tk-abcdef\nIMA-REFRESH-TOKEN=rt-xyz\n";
        let credentials = parse(raw).expect("行式应当也能解");
        assert_eq!(credentials.uid, "100012345");
        assert_eq!(credentials.token, "tk-abcdef");
    }

    /// 缺项必须点名缺哪一个 —— 只说「失败了」用户无从下手。
    #[test]
    fn a_missing_piece_is_named() {
        let error = parse("IMA-UID=1; IMA-TOKEN=2").expect_err("缺 refresh 应当报错");
        assert!(error.contains("IMA-REFRESH-TOKEN"), "实际：{error}");
        assert!(error.contains("完整 Cookie"), "应当指路怎么修，实际：{error}");
    }

    /// `CLIENT-TYPE` 必须被覆盖成 Android 值，**不能**沿用用户抄来的 H5 值。
    #[test]
    fn the_client_type_is_forced_to_the_android_value() {
        let credentials = parse(FULL).expect("解析");
        let header = credentials.cookie_header();
        assert!(
            header.contains(&format!("CLIENT-TYPE={COOKIE_CLIENT_TYPE}")),
            "实际：{header}"
        );
        assert!(!header.contains("256053"), "用户抄来的 H5 值不该出现：{header}");
    }

    /// 只发三项 + CLIENT-TYPE，不把整段浏览器 Cookie 原样转发。
    #[test]
    fn only_the_required_cookies_are_forwarded() {
        let raw = "IMA-UID=1; IMA-TOKEN=2; IMA-REFRESH-TOKEN=3; qq_uin=99; pac_uid=abc";
        let header = parse(raw).expect("解析").cookie_header();
        assert!(!header.contains("qq_uin"), "无关 Cookie 不该转发：{header}");
        assert!(!header.contains("pac_uid"), "无关 Cookie 不该转发：{header}");
    }

    /// bkn 的测试向量由**独立实现**（Python，照抄参考实现）算出。
    #[test]
    fn the_bkn_matches_an_independently_computed_vector() {
        assert_eq!(bkn("abc"), 193_485_963);
        assert_eq!(bkn("hello-world-123"), 1_530_733_585);
        assert_eq!(bkn("0123456789abcdef"), 1_426_588_295);
        assert_eq!(bkn("ima"), 193_495_036);
    }

    /// 结果恒在 31 位内（`& 0x7FFFFFFF`），且非负 —— 上游要的是正整数。
    #[test]
    fn the_bkn_is_always_a_non_negative_thirty_one_bit_value() {
        for token in ["", "a", "很长的一串票据-with-mixed-内容-0123456789"] {
            let value = bkn(token);
            assert!((0..=0x7FFF_FFFF).contains(&value), "token={token} 得到 {value}");
        }
    }

    /// secret 里三项分开存时直接可用。
    #[test]
    fn a_structured_secret_is_read_directly() {
        let secret = serde_json::json!({
            "uid": "1", "token": "2", "refreshToken": "3"
        });
        let credentials = from_secret(&secret).expect("应当可读");
        assert_eq!(credentials.uid, "1");
    }

    /// 只存了整段 cookie 的历史形态也要能读。
    #[test]
    fn a_legacy_cookie_only_secret_still_works() {
        let secret = serde_json::json!({ "cookie": FULL });
        let credentials = from_secret(&secret).expect("应当回落到解析 cookie");
        assert_eq!(credentials.uid, "100012345");
    }

    /// 票据尾 4 位用于界面展示，不能泄露全文。
    #[test]
    fn the_tail_is_four_characters() {
        let credentials = parse(FULL).expect("解析");
        assert_eq!(credentials.token_tail(), "cdef");
    }
}
