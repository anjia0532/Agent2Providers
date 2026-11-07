//! MiniMax Code 的 OAuth **设备码 + PKCE** 登录流程。
//!
//! ── 链路（与官方开源实现 `MiniMax-AI/minimax-code` 逐字对拍）──────
//! ```text
//!   1. POST {accountHost}/oauth2/device/code
//!        body: client_id / scope / audience / code_challenge / code_challenge_method=S256
//!        ← { device_code, user_code, verification_uri, expires_in, interval }
//!   2. 用户在 verification_uri_complete（优先）或 verification_uri 上授权；
//!   3. POST {accountHost}/oauth2/token
//!        body: grant_type=urn:ietf:params:oauth:grant-type:device_code
//!              / device_code / client_id / code_verifier
//!      ← { access_token, refresh_token, token_type, expires_in, scope }
//! ```
//!
//! ── 三条硬校验（照官方 `parseTokenGrant`，不满足即视为无效凭据）────
//!   · `access_token` 非空；
//!   · `refresh_token` 非空（缺失时回退上一个）；
//!   · `token_type` 是 `bearer`；
//!   · `expires_in` 是正数；
//!   · **`scope` 必须含产品声明的 scope**（默认 `agent.default`），
//!     否则上游会以 `invalid_token_response` 拒掉后续请求。
//!
//! ── 过期时间以 `expires_in` 为准 ──────────────────────────────
//! 实测 `access_token` **不是 JWT**（`mmoat_` 前缀、60 字符、0 个点）。
//! 解 JWT 只会恒不命中，所以过期时间只能由 `expires_in` 现算。

use agent2api_provider_sdk::PluginCtx;
use serde_json::{json, Value};

use super::region::Region;
use crate::http;

/// 设备码授权会话（`login.start` 与 `login.poll` 之间在插件进程内传递）。
#[derive(Clone, Debug)]
pub struct DeviceAuth {
    pub device_code: String,
    pub code_verifier: String,
    pub user_code: String,
    /// 授权页（不含 user_code，作为 `verification_uri_complete` 缺失时的兜底）
    pub verification_uri: String,
    /// 含 `user_code` 的完整授权链接（**优先用它**，用户点开即完成）
    pub verification_uri_complete: String,
    /// 轮询间隔（毫秒）
    pub interval_ms: i64,
}

/// 一次令牌授予的结果。
#[derive(Clone, Debug, Default)]
pub struct TokenGrant {
    pub access_token: String,
    pub refresh_token: String,
    /// 绝对到期时刻（毫秒）
    pub expires_at: i64,
}

/// 生成 PKCE `code_verifier`（43–128 字符的 URL-safe 随机串）。
pub fn new_code_verifier() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    let _ = getrandom::getrandom(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `code_challenge = base64url(sha256(verifier))`（S256，无填充）。
pub fn code_challenge(verifier: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// 申请设备码。失败时返回可读文案。
pub async fn request_device_code(
    ctx: &PluginCtx,
    region: Region,
    verifier: &str,
) -> Result<DeviceAuth, String> {
    let client = http::control_client(None, &ctx.env.proxy);
    let url = format!("{}{}", region.account_base_url(), super::DEVICE_CODE_PATH);
    let body = json!({
        "client_id": region.client_id(),
        "scope": region.scope(),
        "audience": region.audience(),
        "code_challenge": code_challenge(verifier),
        "code_challenge_method": "S256",
    });
    let (status, payload) = http::post_json(&client, &url, &[], &body)
        .await
        .map_err(|error| format!("MiniMax 设备码申请失败：{error}"))?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "MiniMax 设备码申请失败（HTTP {status}）：{}",
            readable(&payload)
        ));
    }
    let device_code = text(&payload, &["device_code"]).ok_or_else(|| {
        "MiniMax 设备码响应缺少 device_code，无法继续登录".to_string()
    })?;
    let user_code = text(&payload, &["user_code"])
        .ok_or_else(|| "MiniMax 设备码响应缺少 user_code，无法继续登录".to_string())?;
    let verification_uri = text(&payload, &["verification_uri"])
        .or_else(|| text(&payload, &["verification_url"]))
        .ok_or_else(|| "MiniMax 设备码响应缺少 verification_uri，无法继续登录".to_string())?;
    let verification_uri_complete =
        text(&payload, &["verification_uri_complete"]).unwrap_or_else(|| verification_uri.clone());
    // interval 单位是**秒**；缺省 5 秒（照官方客户端的默认值）
    let interval_ms = payload
        .get("interval")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .unwrap_or(5)
        * 1000;
    Ok(DeviceAuth {
        device_code,
        code_verifier: verifier.to_string(),
        user_code,
        verification_uri,
        verification_uri_complete,
        interval_ms,
    })
}

/// 轮询一次设备码授权（`login.poll` 用）。
pub enum PollResult {
    /// 用户还没授权，稍后再问
    Pending,
    /// 授权完成
    Done(TokenGrant),
    /// 流程结束（过期 / 拒绝 / 上游错误），附可读文案
    Failed(String),
}

/// 用设备码换令牌。
pub async fn poll_device_code(
    ctx: &PluginCtx,
    region: Region,
    auth: &DeviceAuth,
) -> PollResult {
    let client = http::control_client(None, &ctx.env.proxy);
    let url = format!("{}{}", region.account_base_url(), super::TOKEN_PATH);
    let body = json!({
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": auth.device_code,
        "client_id": region.client_id(),
        "code_verifier": auth.code_verifier,
    });
    let (status, payload) = match http::post_json(&client, &url, &[], &body).await {
        Ok(result) => result,
        Err(error) => return PollResult::Failed(format!("MiniMax 登录轮询失败：{error}")),
    };
    // 设备码流程的「还没授权」是**业务态**：上游用 400 + authorization_pending
    let lowered = readable(&payload).to_lowercase();
    if lowered.contains("authorization_pending") {
        return PollResult::Pending;
    }
    if lowered.contains("slow_down") {
        // 网关会按自己的节奏重试；这里如实回 Pending，不报错
        return PollResult::Pending;
    }
    if lowered.contains("expired_token") || lowered.contains("expired device code") {
        return PollResult::Failed("MiniMax 设备码已过期，请重新发起登录".to_string());
    }
    if !(200..300).contains(&status) {
        return PollResult::Failed(format!(
            "MiniMax 登录失败（HTTP {status}）：{}",
            readable(&payload)
        ));
    }
    match parse_token_grant(&payload, "") {
        Ok(grant) => PollResult::Done(grant),
        Err(message) => PollResult::Failed(message),
    }
}

/// 用 refresh_token 换一对新令牌。
pub async fn refresh(
    ctx: &PluginCtx,
    region: Region,
    refresh_token: &str,
) -> Result<TokenGrant, String> {
    let client = http::control_client(None, &ctx.env.proxy);
    let url = format!("{}{}", region.account_base_url(), super::TOKEN_PATH);
    let body = json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": region.client_id(),
        "scope": region.scope(),
        "audience": region.audience(),
    });
    let (status, payload) = http::post_json(&client, &url, &[], &body)
        .await
        .map_err(|error| format!("MiniMax 续期失败：{error}"))?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "MiniMax 续期失败（HTTP {status}）：{}",
            readable(&payload)
        ));
    }
    // refresh_token 可能不被轮换：缺失时回退传进来的那个
    parse_token_grant(&payload, refresh_token)
}

/// 解析令牌响应（轮询与续期共用）。
pub fn parse_token_grant(payload: &Value, previous_refresh: &str) -> Result<TokenGrant, String> {
    let access_token = text(payload, &["access_token"])
        .ok_or_else(|| "MiniMax 令牌响应缺少 access_token".to_string())?;
    let refresh_token = text(payload, &["refresh_token"])
        .or_else(|| {
            (!previous_refresh.is_empty()).then(|| previous_refresh.to_string())
        })
        .ok_or_else(|| "MiniMax 令牌响应缺少 refresh_token".to_string())?;
    let token_type = text(payload, &["token_type"]).unwrap_or_default();
    if !token_type.eq_ignore_ascii_case("bearer") {
        return Err("MiniMax 令牌响应的 token_type 不是 Bearer".to_string());
    }
    let expires_in = payload
        .get("expires_in")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| "MiniMax 令牌响应缺少 expires_in".to_string())?;
    // scope 必须含产品声明的那个，否则后续请求会被上游拒
    let scope = text(payload, &["scope"]).unwrap_or_default();
    if !scope.split_whitespace().any(|item| item == super::SCOPE) {
        return Err(format!(
            "MiniMax 令牌响应的 scope 不含 {}，请在授权页勾选对应权限后重试",
            super::SCOPE
        ));
    }
    Ok(TokenGrant {
        access_token,
        refresh_token,
        expires_at: http::now_ms() + expires_in * 1000,
    })
}

/// 读一个非空字符串字段（大小写不敏感的第一命中）。
fn text(payload: &Value, keys: &[&str]) -> Option<String> {
    let object = payload.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// 把错误体读成一句人可读文案（禁止把整坨 JSON 抛给用户）。
fn readable(payload: &Value) -> String {
    let nested = payload
        .get("error")
        .and_then(|error| error.as_object())
        .and_then(|object| object.get("message"))
        .and_then(Value::as_str);
    let parts: Vec<&str> = [
        payload.get("message").and_then(Value::as_str),
        nested,
        payload.get("msg").and_then(Value::as_str),
        payload.get("error_description").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|text| !text.is_empty())
    .collect();
    if parts.is_empty() {
        return "（上游未返回错误详情）".to_string();
    }
    parts.join(" ")
}
