//! 七牛云凭证：**只有一条来源** —— 账号记录里的 API Key（官方明示 `sk-` 开头）。
//!
//! ── 为什么只要一个字段 ────────────────────────────────────────
//! 七牛云 AI 的凭据是用户在控制台手工生成的 API Key，没有 OAuth 授权页、
//! 没有 refresh 端点（上游只有 `/v1/*` 的 OpenAI 兼容接口）。
//!
//! ── 没有续期 ────────────────────────────────────────────────
//! Key 默认长期有效，因此 `refresh = false`；失效只能去控制台重新生成一个。
//!
//! ── 备份字段 ────────────────────────────────────────────────
//! `accessToken` 是网关的落盘名；粘贴形态另外兼容 `apiKey` / `token` /
//! `session` —— 用户从别处复制过来的 JSON 里字段名并不统一。

use serde_json::Value;

/// 从一条取值链里挑第一个非空字符串（记录可能被手工编辑过，宽容读取）
fn pick(record: &Value, keys: &[&str]) -> String {
    for key in keys {
        let value = record
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("");
        if !value.is_empty() {
            return value.to_string();
        }
    }
    String::new()
}

/// 从账号的 `secret` 里取 API Key（**唯一入口**）。
pub fn api_key_of(secret: &Value) -> Result<String, String> {
    let key = pick(secret, &["accessToken", "apiKey", "token", "session"]);
    if key.is_empty() {
        return Err("七牛云账号缺少 API Key，请重新粘贴".to_string());
    }
    Ok(key)
}

/// 从**上传的 payload** 里取 API Key（添加路径专用：先取出来去探活，再落账号）。
///
/// 与 [`api_key_of`] 的取值链**逐字相同** —— 两处口径分叉的话，「能探活成功
/// 却落不进账号」或反之都会变成难查的静默问题。
pub fn api_key_from_payload(payload: &Value) -> String {
    pick(payload, &["accessToken", "apiKey", "token", "session"])
}

/// API Key 的形态检查：`sk-` 前缀 + 其后只含字母数字与 `_` `-`。
///
/// 只做**形态**检查，不做归一：七牛云的 Key 是逐字下发的凭据，
/// 任何「顺手修一下」都会让用户贴进一个上游不认的串。
pub fn shape_ok(key: &str) -> bool {
    let Some(body) = key.strip_prefix(crate::providers::qiniu::KEY_PREFIX) else {
        return false;
    };
    !body.is_empty()
        && body
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

/// Key 尾 4 字符（公开形态与默认备注名用）。
///
/// 按 `char` 取而不按字节切：粘贴形态的输入框不做格式校验，一个带汉字的
/// 误粘贴就能让按字节回切落在多字节字符中间。
pub fn key_tail(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}
