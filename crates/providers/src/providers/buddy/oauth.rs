//! CodeBuddy 的 OAuth 登录：**浏览器授权 + 轮询**（无 PKCE，回调由服务端记录）。
//!
//! ── 链路（逆向自官方 IDE）────────────────────────────────────
//! ```text
//!   1. POST {endpoint}/v2/plugin/auth/state?platform=ide
//!        ← {data:{state, authUrl}}
//!   2. 用户打开 authUrl 完成登录（服务端把登录态记在那个 state 上）；
//!   3. GET  {endpoint}/v2/plugin/auth/token?state=…   （轮询）
//!        code 11217 = token 尚未就绪 → 继续轮询；网络错误同样继续；
//!        ← {data:{accessToken, refreshToken, expiresAt, refreshExpiresAt,
//!                 tokenType, scope, domain}}
//!   4. GET  {endpoint}/v2/plugin/login/account?state=…（轮询，需 Bearer）
//!        code 12151 = 账户信息尚未完成 → 继续轮询；
//!        ← {data:{uid, nickname, enterpriseId, accountType}}
//!   5. 续期：POST {endpoint}/v2/plugin/auth/token/refresh
//!        头 X-Refresh-Token: <refresh_token>
//! ```
//!
//! ── 两条硬事实 ──────────────────────────────────────────────
//!   · **`expiresAt` 不是必填**：实测 `/v2/plugin/auth/token` 只回相对的
//!     `expiresIn`，绝对值要自己现算（或从 access_token 这个 JWT 的 `exp` 解）；
//!   · **`refresh_token` 会被轮换**：续期响应里没有它时要沿用旧的。

use agent2api_provider_sdk::PluginCtx;
use serde_json::{json, Value};

use super::BUDDY;
use crate::http;

/// 一次登录流程里需要跨 RPC 携带的状态（编进 flow 串）。
#[derive(Clone, Debug, Default)]
pub struct LoginSession {
    pub state: String,
    pub auth_url: String,
}

/// 申请登录态：拿到 state 与授权页地址。
pub async fn start(ctx: &PluginCtx) -> Result<LoginSession, String> {
    let url = format!(
        "{}{}?platform={}",
        BUDDY.endpoint, AUTH_STATE_PATH, BUDDY.platform
    );
    let headers = vec![
        ("X-Domain".to_string(), BUDDY.api_domain.to_string()),
        ("X-No-Authorization".to_string(), "true".to_string()),
        ("X-No-User-Id".to_string(), "true".to_string()),
        ("X-No-Enterprise-Id".to_string(), "true".to_string()),
        ("X-No-Department-Info".to_string(), "true".to_string()),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
    ];
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = http::post_json(&client, &url, &headers, &json!({}))
        .await
        .map_err(|error| format!("CodeBuddy 登录初始化失败：{error}"))?;
    if status != 200 {
        return Err(format!(
            "CodeBuddy 登录初始化失败（HTTP {status}）：{}",
            message(&payload)
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let state = text(&data, &["state"])
        .ok_or_else(|| "CodeBuddy 登录响应缺少 state，无法继续".to_string())?;
    let auth_url = text(&data, &["authUrl"])
        .ok_or_else(|| "CodeBuddy 登录响应缺少 authUrl，无法继续".to_string())?;
    Ok(LoginSession { state, auth_url })
}

/// 轮询一次令牌。
pub enum TokenPoll {
    /// 还没就绪，稍后再问
    Pending,
    /// 拿到了
    Done(TokenGrant),
    /// 流程结束（失败），附可读文案
    Failed(String),
}

/// 一次令牌授予。
#[derive(Clone, Debug, Default)]
pub struct TokenGrant {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub refresh_expires_at: i64,
    pub domain: String,
}

/// 轮询 `auth/token`（code 11217 = 未就绪）。
pub async fn poll_token(ctx: &PluginCtx, state: &str) -> TokenPoll {
    let url = format!(
        "{}{}?state={}",
        BUDDY.endpoint,
        AUTH_TOKEN_PATH,
        url_encode(state)
    );
    let headers = vec![
        ("X-No-Authorization".to_string(), "true".to_string()),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
    ];
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = match http::get_json(&client, &url, &headers).await {
        Ok(result) => result,
        // 网络错误：继续轮询，不中断登录流程（对齐官方 loop_get_token）
        Err(_) => return TokenPoll::Pending,
    };
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if status == 200 && code == 0 {
        let data = payload.get("data").cloned().unwrap_or(Value::Null);
        let access_token = match text(&data, &["accessToken", "access_token"]) {
            Some(token) if !token.is_empty() => token,
            _ => return TokenPoll::Failed("CodeBuddy 登录响应缺少 accessToken".to_string()),
        };
        // 绝对过期时刻：优先服务端给的 expiresAt，否则用 expiresIn 现算，
        // 最后兜底从 access_token 这个 JWT 的 exp 解
        let expires_at = text(&data, &["expiresAt"])
            .and_then(|raw| parse_timestamp(&raw))
            .or_else(|| {
                data.get("expiresIn")
                    .and_then(Value::as_i64)
                    .filter(|value| *value > 0)
                    .map(|seconds| http::now_ms() + seconds * 1000)
            })
            .or_else(|| jwt_expires_at(&access_token))
            .unwrap_or(0);
        let refresh_expires_at = text(&data, &["refreshExpiresAt"])
            .and_then(|raw| parse_timestamp(&raw))
            .or_else(|| {
                data.get("refreshExpiresIn")
                    .and_then(Value::as_i64)
                    .filter(|value| *value > 0)
                    .map(|seconds| http::now_ms() + seconds * 1000)
            })
            .unwrap_or(0);
        return TokenPoll::Done(TokenGrant {
            access_token,
            refresh_token: text(&data, &["refreshToken", "refresh_token"]).unwrap_or_default(),
            expires_at,
            refresh_expires_at,
            domain: text(&data, &["domain"]).unwrap_or_default(),
        });
    }
    if code == CODE_TOKEN_NOT_READY {
        return TokenPoll::Pending;
    }
    TokenPoll::Failed(format!(
        "CodeBuddy 登录失败（HTTP {status} code={code}）：{}",
        message(&payload)
    ))
}

/// 一次账户信息。
#[derive(Clone, Debug, Default)]
pub struct Account {
    pub uid: String,
    pub nickname: String,
    pub enterprise_id: String,
    pub account_type: String,
}

/// 轮询 `login/account`（code 12151 = 未就绪）。
pub enum AccountPoll {
    Pending,
    Done(Account),
    Failed(String),
}

/// 轮询账户信息（需要 Bearer token）。
pub async fn poll_account(
    ctx: &PluginCtx,
    state: &str,
    access_token: &str,
    domain: &str,
) -> AccountPoll {
    let url = format!(
        "{}{}?state={}",
        BUDDY.endpoint,
        LOGIN_ACCOUNT_PATH,
        url_encode(state)
    );
    let headers = vec![
        ("X-Domain".to_string(), domain.to_string()),
        ("Authorization".to_string(), format!("Bearer {access_token}")),
        ("X-No-User-Id".to_string(), "true".to_string()),
        ("X-No-Enterprise-Id".to_string(), "true".to_string()),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
    ];
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = match http::get_json(&client, &url, &headers).await {
        Ok(result) => result,
        Err(_) => return AccountPoll::Pending,
    };
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if status == 200 && code == 0 {
        let data = payload.get("data").cloned().unwrap_or(Value::Null);
        return AccountPoll::Done(Account {
            uid: text(&data, &["uid"]).unwrap_or_default(),
            nickname: text(&data, &["nickname"]).unwrap_or_default(),
            enterprise_id: text(&data, &["enterpriseId"]).unwrap_or_default(),
            account_type: text(&data, &["accountType"]).unwrap_or_default(),
        });
    }
    if code == CODE_ACCOUNT_NOT_READY {
        return AccountPoll::Pending;
    }
    AccountPoll::Failed(format!(
        "CodeBuddy 账户信息获取失败（HTTP {status} code={code}）：{}",
        message(&payload)
    ))
}

/// 续期：`POST /v2/plugin/auth/token/refresh`，头 `X-Refresh-Token`。
pub async fn refresh(
    ctx: &PluginCtx,
    refresh_token: &str,
    domain: &str,
) -> Result<TokenGrant, String> {
    let url = format!("{}{}", BUDDY.endpoint, AUTH_REFRESH_PATH);
    let headers = vec![
        ("X-Domain".to_string(), domain.to_string()),
        ("X-Refresh-Token".to_string(), refresh_token.to_string()),
        ("X-Auth-Refresh-Source".to_string(), AUTH_REFRESH_SOURCE.to_string()),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let client = http::control_client(None, &ctx.env.proxy);
    let (status, payload) = http::post_json(&client, &url, &headers, &json!({}))
        .await
        .map_err(|error| format!("CodeBuddy 续期失败：{error}"))?;
    // 401/403 或文案含 expired/invalid ⇒ refresh_token 已失效
    let lowered = message(&payload).to_lowercase();
    if status == 401 || status == 403 || lowered.contains("expired") || lowered.contains("invalid") {
        return Err("CodeBuddy 登录态已失效，请重新登录该账号".to_string());
    }
    if status != 200 {
        return Err(format!(
            "CodeBuddy 续期失败（HTTP {status}）：{}",
            message(&payload)
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let access_token = text(&data, &["accessToken", "access_token"])
        .ok_or_else(|| "CodeBuddy 续期响应缺少 accessToken".to_string())?;
    let expires_at = text(&data, &["expiresAt"])
        .and_then(|raw| parse_timestamp(&raw))
        .or_else(|| {
            data.get("expiresIn")
                .and_then(Value::as_i64)
                .filter(|value| *value > 0)
                .map(|seconds| http::now_ms() + seconds * 1000)
        })
        .or_else(|| jwt_expires_at(&access_token))
        .unwrap_or(0);
    Ok(TokenGrant {
        // refresh_token 可能被轮换，缺失时沿用旧的
        refresh_token: text(&data, &["refreshToken", "refresh_token"])
            .unwrap_or_else(|| refresh_token.to_string()),
        access_token,
        expires_at,
        refresh_expires_at: text(&data, &["refreshExpiresAt"])
            .and_then(|raw| parse_timestamp(&raw))
            .unwrap_or(0),
        domain: text(&data, &["domain"]).unwrap_or_default(),
    })
}

/// token 尚未就绪（继续轮询）。
pub const CODE_TOKEN_NOT_READY: i64 = 11217;
/// 账户信息尚未完成（继续轮询）。
pub const CODE_ACCOUNT_NOT_READY: i64 = 12151;
/// 刷新来源标识（对齐官方 IDE）。
pub const AUTH_REFRESH_SOURCE: &str = "ide-main";

const AUTH_STATE_PATH: &str = "/v2/plugin/auth/state";
const AUTH_TOKEN_PATH: &str = "/v2/plugin/auth/token";
const LOGIN_ACCOUNT_PATH: &str = "/v2/plugin/login/account";
const AUTH_REFRESH_PATH: &str = "/v2/plugin/auth/token/refresh";

/// 从 JWT 的 payload 读 `exp`（秒）并换算成毫秒；非 JWT 或解析失败返回 None。
///
/// 仅做 base64url 解码，**不验签** —— 该值只用于展示与续期调度。
fn jwt_expires_at(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload))
        .ok()?;
    let parsed: Value = serde_json::from_slice(&bytes).ok()?;
    parsed
        .get("exp")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .map(|seconds| seconds * 1000)
}

/// 解析时间戳：纯数字（>1e12 视为毫秒，否则秒）或 ISO 8601。
fn parse_timestamp(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(if value > 1_000_000_000_000 { value } else { value * 1000 });
    }
    None
}

/// 最小 URL 编码（只转义 query 里不允许的字符）。
fn url_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn text(record: &Value, keys: &[&str]) -> Option<String> {
    let object = record.as_object()?;
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

fn message(payload: &Value) -> String {
    let parts: Vec<&str> = [
        payload.get("msg").and_then(Value::as_str),
        payload.get("message").and_then(Value::as_str),
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
