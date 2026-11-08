//! ima（腾讯 **ima.copilot**）插件实现：**Cookie 认证 + 两步会话 + SSE**。
//!
//! ── 上游形态 ────────────────────────────────────────────────
//! ```text
//!   POST https://ima.qq.com/cgi-bin/session_logic/init_session   → session_id
//!   POST https://ima.qq.com/cgi-bin/assistant/qa                  → SSE 正文
//!   POST https://ima.qq.com/cgi-bin/model_manage/get_models       → 模型目录
//!   Cookie: IMA-UID / IMA-TOKEN / IMA-REFRESH-TOKEN / CLIENT-TYPE
//! ```
//!
//! ── 为什么是 `stateful`（走 `conversation()`）──────────────────
//! 一次对话要发**两次** HTTP（先建会话拿 `session_id`，再提问）。而
//! `build_chat` 的产物 `ChatPlan` 只能表达一次请求 —— 硬塞进 `build_chat`
//! 就得在那里同步发一次请求，把「构造计划」和「发请求」搅在一起。
//! `conversation()` 的推模型天生支持多次请求，所以本家申报 `stateful: true`。
//!
//! ── 三条实测出来的硬约束（来自参考实现 `DistPub/ima2api`）───────
//! 1. **`CLIENT-TYPE` 必须是客户端值**（Android `256001`）。浏览器 H5 的值
//!    （`256053`）会被拒，报「当前版本暂不支持」。用户抄来的 Cookie 里是 H5 值，
//!    所以这里**无条件覆盖**（见 [`credentials`]）。
//! 2. **默认走普通通道**（`robot_type = 10000`）而不是 copilot（`15`）：
//!    copilot 的默认池含沙盒 agent 模型，工具调用被沙盒自执行、**不透传**；
//!    显式指定模型还会被 `102005` 锁死。普通通道是纯对话模型池。
//! 3. **没有自动续期**：刷新接口在 ima 原生层。所以 `refresh: false`，
//!    票据过期时如实报错并指路「去网页重新复制 Cookie」，不假装能续。
//!
//! ── 归属 ────────────────────────────────────────────────────
//! 协议细节来自 `DistPub/ima2api`（Python，2026-10-31 定稿，含真实抓包验证）。
//! 本实现是**照协议重写**，没有复制它的代码。

pub mod chat;
pub mod credentials;
pub mod events;
pub mod models;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use crate::http;

/// provider id（`pack.json` 里也要写同一个）
pub const ID: &str = "ima";

/// `Cookie` 里的 `CLIENT-TYPE`：**Android 客户端值**。
///
/// 浏览器 H5 的值是 `256053`，会被上游拒（「当前版本暂不支持」）。
/// 这个常量存在的唯一理由就是**覆盖**用户抄来的那个 H5 值。
pub const COOKIE_CLIENT_TYPE: &str = "256001";

/// 出站 User-Agent（网页版同款；上游对默认 UA 敏感）。
pub const USER_AGENT: &str = concat!(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ",
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
);

/// ima 适配器。
pub struct ImaProvider;

impl Provider for ImaProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "ima 腾讯")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 一次转发 = 建会话 + SSE 两步（见模块头）
                stateful: true,
                // 刷新接口在 ima 原生层，无法自动续期
                refresh: false,
                model_refresh: true,
                usage: false,
                checkin: false,
                claims: false,
                // 只能粘贴 Cookie，没有可拉起的授权页
                web_login: false,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![proto::LoginMethod::Token {
                label: "ima 登录态（Cookie）".to_string(),
                placeholder: "粘贴 ima.qq.com 的完整 Cookie（含 IMA-UID / IMA-TOKEN / IMA-REFRESH-TOKEN）"
                    .to_string(),
                extra_fields: Vec::new(),
            }])
            .with_models(models::fallback_models())
            .with_account_features(proto::AccountFeatures {
                usage: false,
                identifier: vec!["id".to_string()],
                ..Default::default()
            })
    }

    fn provider_id(&self) -> String {
        ID.to_string()
    }

    // ── 转发 ──────────────────────────────────────────────────

    /// 本家走 `conversation()`，`build_chat` 只在网关误用时才会被调到。
    ///
    /// 返回**可读的错误**而不是 panic：这里被调到的唯一可能是网关侧状态判定
    /// 出了偏差，那种情况要给一条能照着改的提示，而不是一次崩溃。
    fn build_chat<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async {
            Err(
                "ima 需要「建会话 + 提问」两步，必须走会话式转发（conversation）；\
                 若看到这条说明网关侧的能力判定把本家当成了单步请求型"
                    .to_string(),
            )
        })
    }

    fn conversation<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ConversationRequest,
        sink: agent2api_provider_sdk::ConversationSink<'a>,
    ) -> SendFuture<'a, ()> {
        Box::pin(chat::run(ctx, req, sink))
    }

    /// 上游错误分类。
    ///
    /// 登录过期（HTTP 401 / 业务码 `600001`）归 `TokenExpired` —— 语义上它**确实**
    /// 是票据失效，只是本家没有续期能力，所以命中的账号会一直失败直到用户重新
    /// 粘贴 Cookie。归成 `Fatal` 也对，但 `TokenExpired` 能让界面提示「重新登录」。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let code = errors::code_of(body);
        if status == 401 || code == Some(600_001) || code == Some(401) {
            return proto::ErrorClass::TokenExpired {
                message: format!("{message}（ima 登录态已过期，且本家无法自动续期：请重新复制 Cookie）"),
            };
        }
        if status == 429 || code == Some(429) {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: code,
                status: 429,
            };
        }
        proto::ErrorClass::Fatal {
            status: if status >= 500 { status } else { 502 },
            message,
            upstream_code: code,
        }
    }

    // ── 凭证 ──────────────────────────────────────────────────

    /// 返回**访问票据**（`IMA-TOKEN`）。本家没有续期，所以这里只读不刷。
    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, account)
                .await
                .map_err(|error| format!("读取 ima 账号失败：{error}"))?;
            Ok(credentials::from_secret(&found.secret)?.token)
        })
    }

    // ── 目录 ──────────────────────────────────────────────────

    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move {
            Ok(proto::ModelList {
                models: models::fallback_models(),
                meta: proto::CatalogMeta { remote: false, refreshed_at: 0 },
            })
        })
    }

    /// 拉上游目录（`scene = 0`，普通问答池）。
    ///
    /// 需要账号：与七牛云 / OrcaRouter 那种「目录免鉴权」不同，本家的
    /// `get_models` 要 Cookie。所以没有账号时如实返回失败，界面退回静态兜底。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let _ = force;
            let found = match ctx.store_get(ID, account).await {
                Ok(found) => found,
                Err(error) => {
                    return Ok(proto::RefreshOutcome::failed(format!("读取 ima 账号失败：{error}")))
                }
            };
            let credentials = match credentials::from_secret(&found.secret) {
                Ok(credentials) => credentials,
                Err(error) => return Ok(proto::RefreshOutcome::failed(error)),
            };
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(match chat::fetch_models(&client, &credentials, 0).await {
                Ok(models) if !models.is_empty() => proto::RefreshOutcome::refreshed(models.len()),
                Ok(_) => proto::RefreshOutcome::failed("ima 模型目录为空（保留现有清单）"),
                Err(error) => proto::RefreshOutcome::failed(error),
            })
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            let raw = match &input.source {
                proto::NormalizeSource::Manual { payload } => {
                    // `auth.methods` 申报的 `api` 方式：网关把表单字段装在 `inputs` 下
                    let payload = payload
                        .get("inputs")
                        .filter(|inputs| inputs.is_object())
                        .unwrap_or(payload);
                    payload
                        .get("cookie")
                        .or_else(|| payload.get("key"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_default()
                }
                proto::NormalizeSource::FileText { content, .. } => content.clone(),
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err("ima 不支持二进制文件导入，请粘贴 Cookie".to_string())
                }
                proto::NormalizeSource::Desktop => {
                    return Err(
                        "ima 暂不支持「导入本机客户端登录态」，请从浏览器复制 Cookie 后粘贴"
                            .to_string(),
                    )
                }
            };
            let credentials = credentials::parse(&raw)?;
            let name = "ima".to_string();
            // 三项分开存 + 保留整段（兼容将来需要更多 Cookie 的情形）
            let secret = json!({
                "uid": credentials.uid,
                "token": credentials.token,
                "refreshToken": credentials.refresh_token,
                "cookie": raw.trim(),
                "name": name,
            });
            Ok(proto::NormalizedAccount {
                public: json!({
                    "name": name,
                    "hasCookie": true,
                    "uid": credentials.uid,
                    "tokenTail": credentials.token_tail(),
                }),
                identity: identity_of(&credentials.uid),
                secret,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(identity_of(&credentials::from_secret(secret)?.uid))
    }

    /// `auth.methods`：界面据此渲染「添加账号」表单（一个 Cookie 输入框）。
    fn admin_action<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
        action: &'a str,
        _payload: &'a Value,
    ) -> SendFuture<'a, Value> {
        Box::pin(async move {
            match action {
                "auth.methods" => Ok(login_methods()),
                _ => Err(agent2api_provider_sdk::unsupported(format!(
                    "ima 不支持管理动作「{action}」"
                ))),
            }
        })
    }
}

fn identity_of(uid: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(uid.as_bytes());
    format!("ima-{}", &format!("{:x}", hasher.finalize())[..12])
}

/// 随机十六进制（`bytes` 个字节 → `2 * bytes` 个字符）。
///
/// 用 `getrandom` 而不是时间戳：`client_id` 被上游当成设备标识，同一账号
/// 反复用同一个值有可能被风控归组；用时间戳更是必然重复。
pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut buffer);
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `auth.methods` 的返回：`type: "api"`，一个 secret 输入框。
fn login_methods() -> Value {
    json!({ "methods": [{
        "methodIndex": 0,
        "type": "api",
        "label": "ima.qq.com 登录态（Cookie）",
        "instructions": "在浏览器登录 ima.qq.com，用开发者工具复制**完整 Cookie** 粘贴到这里。必需三项：IMA-UID、IMA-TOKEN、IMA-REFRESH-TOKEN（CLIENT-TYPE 会被网关覆盖成客户端值，不用管）。票据过期后需要重新复制 —— 本家没有可用的自动续期接口。",
        "prompts": [{
            "key": "cookie",
            "type": "text",
            "label": "Cookie",
            "placeholder": "IMA-UID=…; IMA-TOKEN=…; IMA-REFRESH-TOKEN=…",
            "secret": true,
            "optional": false
        }],
        "localOnly": false,
        "manualCallback": false,
        "callbackInput": "url",
        "embeddedOnly": false
    }] })
}

/// 错误文案与业务码抽取。
mod errors {
    use serde_json::Value;

    pub fn message_of(body: &Value) -> String {
        let parts: Vec<&str> = [
            body.get("msg").and_then(Value::as_str),
            body.get("message").and_then(Value::as_str),
            body.pointer("/error/message").and_then(Value::as_str),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .collect();
        if parts.is_empty() {
            return "上游未返回错误详情".to_string();
        }
        parts.join(" ")
    }

    pub fn code_of(body: &Value) -> Option<i64> {
        body.get("code")
            .and_then(Value::as_i64)
            .or_else(|| body.get("Code").and_then(Value::as_i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 登录过期（HTTP 401）要归到 `TokenExpired`，界面才会提示「重新登录」。
    #[test]
    fn an_expired_cookie_is_a_token_expiry() {
        let class = ImaProvider.classify(401, &json!({ "msg": "登录过期" }));
        let proto::ErrorClass::TokenExpired { message } = class else {
            panic!("401 应当归到 TokenExpired");
        };
        assert!(message.contains("无法自动续期"), "实际：{message}");
        assert!(message.contains("Cookie"), "应当指路怎么修，实际：{message}");
    }

    /// 业务码 600001（HTTP 200 但登录过期）也要能认出来。
    #[test]
    fn the_expired_business_code_is_also_recognised() {
        let class = ImaProvider.classify(200, &json!({ "code": 600001, "msg": "登录过期，请重新登录" }));
        assert!(matches!(class, proto::ErrorClass::TokenExpired { .. }));
    }

    /// 限流归 `QuotaLimited`（要换号），不是 `Fatal`。
    #[test]
    fn a_rate_limit_is_a_quota_condition() {
        assert!(matches!(
            ImaProvider.classify(429, &json!({})),
            proto::ErrorClass::QuotaLimited { .. }
        ));
    }

    /// 5xx 原样带上状态码；其余归 502（网关侧的通用上游错误）。
    #[test]
    fn server_errors_keep_their_status() {
        let class = ImaProvider.classify(503, &json!({ "msg": "busy" }));
        let proto::ErrorClass::Fatal { status, .. } = class else {
            panic!("应当是 Fatal");
        };
        assert_eq!(status, 503);

        let class = ImaProvider.classify(400, &json!({ "msg": "bad" }));
        let proto::ErrorClass::Fatal { status, .. } = class else {
            panic!("应当是 Fatal");
        };
        assert_eq!(status, 502);
    }

    /// 身份由 uid 摘要生成：稳定、不同 uid 不同。
    #[test]
    fn identity_is_stable_and_uid_specific() {
        assert_eq!(identity_of("1001"), identity_of("1001"));
        assert_ne!(identity_of("1001"), identity_of("1002"));
        assert!(identity_of("1001").starts_with("ima-"));
    }

    /// `random_hex` 长度正确、每次不同、全小写十六进制。
    #[test]
    fn random_hex_is_fresh_and_lowercase() {
        let first = random_hex(8);
        let second = random_hex(8);
        assert_eq!(first.len(), 16);
        assert_ne!(first, second);
        assert!(first.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    /// 本家必须是 stateful —— 否则网关会去调 `build_chat`，而它必然报错。
    #[test]
    fn the_provider_declares_itself_stateful() {
        let meta = ImaProvider.meta();
        assert!(meta.capabilities.stateful, "ima 需要两步请求，必须申报 stateful");
        assert!(meta.capabilities.chat);
        // 没有自动续期能力，不能申报 refresh
        assert!(!meta.capabilities.refresh, "本家没有可用的续期接口");
    }
}
