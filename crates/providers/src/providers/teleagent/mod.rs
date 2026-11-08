//! TeleAgent（中国电信「星辰超级智能体」）插件实现：**云端 API + 本机签名**。
//!
//! ── 与其它家最大的不同：请求要**签名** ──────────────────────
//! 鉴权不是单纯一个 `Authorization`，而是「三条凭据 + 每请求现算签名」：
//!
//! ```text
//!   凭据（用户粘贴，长期有效）：
//!     token      —— JWT（同时进 Authorization 之外的 X-Token 与签名）
//!     deviceId   —— X-SuperAgent-Device-Id
//!     installId  —— X-SuperAgent-Install-Id（同时参与签名）
//!
//!   每请求现算（见 sign.rs）：
//!     nonce / timestamp / signature
//! ```
//!
//! ── 上游端点 ──────────────────────────────────────────────
//! ```text
//!   POST https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions
//! ```
//! 路径里 `superCowork/sapi` 这两段不能省（省了是 404，不是签名错）。
//!
//! ── 没有的能力（如实申报，不假装有）──────────────────────────
//!   · **没有续期**：三条凭据都是长期值，上游没有 refresh 端点 → `refresh = false`；
//!   · **没有目录接口**：模型清单是静态 3 条（见 `models.rs`）→ `model_refresh = false`；
//!   · **没有余额 / 签到**：`usage = false`、`checkin = false`。
//!
//! ── 本期**不做**的一件事：思维链拆分 ─────────────────────────
//! 上游把思维链以 `<think>…</think>` 混在正文里（`chat-pro` 才有）。参考实现的
//! 做法是在响应侧把它抽出来塞进 `reasoning_content`。插件这边要做同样的事，
//! 得在**流式增量**上做跨帧状态机（标签可能被切在两个 chunk 之间），
//! 而 `build_chat` 只负责**出站**。所以本期原样透传：客户端会把 `<think>` 当
//! 正文渲染。要补这一步得走 `conversation()` 那条推模型，属于独立一项工作。

pub mod models;
pub mod sign;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use crate::http;

/// provider id（`pack.json` 里也要写同一个）
pub const ID: &str = "teleagent";

/// 上游基址（不含尾斜杠）
pub const BASE_URL: &str = "https://agent.teleai.com.cn";

/// 对话路径（`superCowork/sapi` 两段不能省）
pub const CHAT_PATH: &str = "/superCowork/sapi/api/v1/chat/completions";

/// `X-App-Version` 与 UA 里报的客户端版本
pub const APP_VERSION: &str = "2.0.0";

/// User-Agent（照抄参考实现实测可用的那一串：把请求伪装成 opencode 客户端）
pub const USER_AGENT: &str =
    "opencode/1.2.27 ai-sdk/provider-utils/3.0.20 runtime/bun/1.3.10";

/// `Authorization: Bearer <...>` 的这个值**不是**用户的 token。
///
/// ── 它是什么 ──────────────────────────────────────────────
/// 参考实现（`T786279007/teleagent2api-deploy` 的 `config.go`）把它当**配置项**
/// 硬编码了一个 `sk-` 前缀的公开应用密钥，同时另用 `X-Token` 装用户的 JWT。
/// 也就是说上游把「应用身份」和「账号身份」拆成了两个头。
///
/// ⚠️ 本插件**没有**独立验证过这个值是否对所有账号通用 —— 它是从参考实现抄来的
/// 常量。若某天上游换了应用密钥，症状会是**所有账号**统一 401（而不是单个账号
/// 失效），届时应优先怀疑这里，而不是用户的 token。
pub const APP_KEY: &str = "sk-qvp4m6h9g20uM6PgYP7E";

/// 从 `secret` 里读三条凭据。
fn credentials_of(secret: &Value) -> Result<(String, String, String), String> {
    let text = |keys: &[&str]| -> String {
        for key in keys {
            if let Some(value) = secret.get(*key).and_then(Value::as_str) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
        String::new()
    };
    let token = text(&["token", "accessToken", "access_token"]);
    if token.is_empty() {
        return Err("TeleAgent 账号缺少 token，请重新粘贴登录态".to_string());
    }
    let device_id = text(&["deviceId", "device_id"]);
    if device_id.is_empty() {
        return Err("TeleAgent 账号缺少 deviceId，请重新粘贴登录态".to_string());
    }
    let install_id = text(&["installId", "install_id"]);
    if install_id.is_empty() {
        return Err("TeleAgent 账号缺少 installId，请重新粘贴登录态".to_string());
    }
    Ok((token, device_id, install_id))
}

/// TeleAgent 适配器。
pub struct TeleagentProvider;

impl Provider for TeleagentProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "TeleAgent 星辰智能体")
            .with_capabilities(proto::Capabilities {
                chat: true,
                stateful: false,
                // 三条凭据都是长期值，上游没有 refresh 端点
                refresh: false,
                // 没有目录接口，清单是静态的
                model_refresh: false,
                usage: false,
                checkin: false,
                claims: false,
                // 只能在客户端里登录后手抄三条凭据，没有可拉起的授权页
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
                label: "TeleAgent 登录态".to_string(),
                placeholder: "粘贴 {\"token\":\"…\",\"deviceId\":\"…\",\"installId\":\"…\"}".to_string(),
                extra_fields: Vec::new(),
            }])
            .with_models(models::list())
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

    /// 构造并**签名**一次对话请求。
    ///
    /// 顺序不能换：签名里的 `bodySHA` 是**最终请求体**的摘要，所以必须先完成
    /// 「`max_tokens` 封顶」这个改写，再签名。签名在前、改体在后 ⇒ 上游算出的
    /// 摘要对不上 ⇒ 签名失败（且报错不会告诉你差在哪一步）。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, &req.account)
                .await
                .map_err(|error| format!("读取 TeleAgent 账号失败：{error}"))?;
            let (token, device_id, install_id) = credentials_of(&found.secret)?;

            let mut body = req.body;
            clamp_max_tokens(&mut body);
            let payload = body.to_string();

            let nonce = sign::new_nonce();
            let timestamp = format!("{}", http::now_ms() / 1000);
            let signed = sign::sign(
                &token,
                &install_id,
                &timestamp,
                &nonce,
                APP_VERSION,
                CHAT_PATH,
                payload.as_bytes(),
            )?;

            let headers = vec![
                ("Authorization".to_string(), format!("Bearer {APP_KEY}")),
                ("Content-Type".to_string(), "application/json".to_string()),
                ("User-Agent".to_string(), USER_AGENT.to_string()),
                ("X-App-Version".to_string(), APP_VERSION.to_string()),
                ("X-Token".to_string(), token.clone()),
                ("X-SuperAgent-Device-Id".to_string(), device_id),
                ("X-SuperAgent-Install-Id".to_string(), install_id),
                ("X-SuperAgent-Nonce".to_string(), signed.nonce.clone()),
                ("X-SuperAgent-Sign-Version".to_string(), sign::SIGN_VERSION.to_string()),
                ("X-SuperAgent-Signature".to_string(), signed.signature.clone()),
                ("X-SuperAgent-Timestamp".to_string(), signed.timestamp.clone()),
                ("x-message-id".to_string(), format!("msg_{}", sign::new_hex_id())),
                ("x-session-id".to_string(), format!("ses_{}", sign::new_hex_id())),
                ("Accept".to_string(), "text/event-stream".to_string()),
                // 与参考实现一致：明确要求不压缩，避免摘要/解压两个层面纠缠
                ("Accept-Encoding".to_string(), "identity".to_string()),
            ];
            Ok(ChatPlan::chat(
                format!("{BASE_URL}{CHAT_PATH}"),
                headers,
                body,
            ))
        })
    }

    /// 上游错误分类。
    ///
    /// ⚠️ **签名失败也是 401** —— 与「token 失效」同码。这里把两种情况分开说，
    /// 否则用户会一直去重新登录，而真正的问题是 `installId` 抄错了。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let lowered = message.to_lowercase();
        if status == 401 || status == 403 {
            let hint = if lowered.contains("sign")
                || lowered.contains("signature")
                || lowered.contains("签名")
            {
                "（看起来是**签名**失败而不是 token 失效：请核对 deviceId / installId 是否与 token 同一台设备）"
            } else {
                "（登录态可能已失效，请重新粘贴 token / deviceId / installId）"
            };
            return proto::ErrorClass::TokenExpired {
                message: format!("{message}{hint}"),
            };
        }
        if status == 429 || lowered.contains("rate limit") || lowered.contains("too many") {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: errors::code_of(body),
                status: 429,
            };
        }
        if lowered.contains("积分") || lowered.contains("quota") || lowered.contains("insufficient") {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: errors::code_of(body),
                status: 429,
            };
        }
        proto::ErrorClass::Fatal {
            status: if status >= 500 { status } else { 502 },
            message,
            upstream_code: errors::code_of(body),
        }
    }

    // ── 凭证 ──────────────────────────────────────────────────

    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, account)
                .await
                .map_err(|error| format!("读取 TeleAgent 账号失败：{error}"))?;
            Ok(credentials_of(&found.secret)?.0)
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
                models: models::list(),
                meta: proto::CatalogMeta {
                    // 静态清单，不是远端拉的
                    remote: false,
                    refreshed_at: 0,
                },
            })
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    /// 手填 / 文件 / `auth.methods` 三条路都收，统一成三条凭据。
    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            let payload = match &input.source {
                proto::NormalizeSource::Manual { payload } => payload.clone(),
                proto::NormalizeSource::FileText { content, .. } => serde_json::from_str::<Value>(content.trim())
                    .map_err(|_| {
                        "TeleAgent 的登录态必须是 JSON：{\"token\":…,\"deviceId\":…,\"installId\":…}"
                            .to_string()
                    })?,
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err("TeleAgent 不支持二进制文件导入，请粘贴登录态 JSON".to_string())
                }
                proto::NormalizeSource::Desktop => {
                    return Err(
                        "TeleAgent 暂不支持「导入本机客户端登录态」，请从客户端复制三条凭据后粘贴"
                            .to_string(),
                    )
                }
            };
            // `auth.methods` 申报的 `api` 方式：网关把表单字段装在 `inputs` 下
            let payload = payload
                .get("inputs")
                .filter(|inputs| inputs.is_object())
                .unwrap_or(&payload);
            let (token, device_id, install_id) = credentials_of(payload)?;
            if sign::jwt_third_segment(&token).is_err() {
                return Err(
                    "TeleAgent 的 token 不是有效 JWT（应为三段点分），请确认复制的是 token 而不是别的东西"
                        .to_string(),
                );
            }
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| "TeleAgent".to_string());
            let secret = json!({
                "token": token,
                "deviceId": device_id,
                "installId": install_id,
                "name": name,
            });
            Ok(proto::NormalizedAccount {
                public: json!({
                    "name": name,
                    "hasToken": true,
                    "tokenTail": tail(&token),
                    "deviceId": device_id,
                }),
                identity: identity_of(&token),
                secret,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        let token = credentials_of(secret)?.0;
        Ok(identity_of(&token))
    }

    /// `auth.methods`：界面据此渲染「添加账号」表单（三个密钥输入框）。
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
                    "TeleAgent 不支持管理动作「{action}」"
                ))),
            }
        })
    }
}

/// 把 `max_tokens` / `max_completion_tokens` 压到该模型的上限以内。
///
/// 上游超限**直接报错**（不像别家静默钳制），而 Claude Code 那类客户端动辄发
/// 128K/200K ⇒ 不封顶就是每个请求都 400。
///
/// 认不出模型时**不动**：猜一个上限会把用户本来合理的小值改大。
fn clamp_max_tokens(body: &mut Value) {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let Some(cap) = models::max_output_of(&model) else {
        return;
    };
    let Some(object) = body.as_object_mut() else {
        return;
    };
    for key in ["max_tokens", "max_completion_tokens"] {
        if let Some(value) = object.get(key).and_then(Value::as_i64) {
            if value > cap as i64 {
                object.insert(key.to_string(), json!(cap));
            }
        }
    }
}

fn identity_of(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("teleagent-{}", &format!("{:x}", hasher.finalize())[..12])
}

fn tail(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// `auth.methods` 的返回：`type: "api"`，三个必填密钥。
fn login_methods() -> Value {
    json!({ "methods": [{
        "methodIndex": 0,
        "type": "api",
        "label": "TeleAgent 登录态（token / deviceId / installId）",
        "instructions": "在 TeleAgent 桌面客户端里取得三条值：token（JWT，形如 aaa.bbb.ccc）、deviceId、installId。三条必须来自**同一台设备**，否则请求签名会失败。",
        "prompts": [
            { "key": "token", "type": "text", "label": "token（JWT）", "placeholder": "eyJ………", "secret": true, "optional": false },
            { "key": "deviceId", "type": "text", "label": "deviceId", "placeholder": "设备 id", "secret": true, "optional": false },
            { "key": "installId", "type": "text", "label": "installId", "placeholder": "安装 id（参与签名）", "secret": true, "optional": false }
        ],
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
            body.get("message").and_then(Value::as_str),
            body.get("msg").and_then(Value::as_str),
            body.pointer("/error/message").and_then(Value::as_str),
            body.pointer("/data/message").and_then(Value::as_str),
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
            .or_else(|| body.pointer("/error/code").and_then(Value::as_i64))
            .or_else(|| body.pointer("/data/code").and_then(Value::as_i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_credential_triple_is_accepted() {
        let secret = json!({ "token": "a.b.c", "deviceId": "d1", "installId": "i1" });
        let (token, device, install) = credentials_of(&secret).expect("三条齐全应当通过");
        assert_eq!(token, "a.b.c");
        assert_eq!(device, "d1");
        assert_eq!(install, "i1");
    }

    /// 三条缺一不可 —— 尤其 installId，它参与签名，缺了只会得到一个笼统的 401。
    #[test]
    fn a_missing_piece_is_named_in_the_error() {
        let message = credentials_of(&json!({ "token": "a.b.c", "deviceId": "d1" }))
            .expect_err("缺 installId 应当报错");
        assert!(message.contains("installId"), "报错要点名缺哪一个，实际：{message}");
    }

    /// 超限的 `max_tokens` 被压到该模型的上限。
    #[test]
    fn an_oversized_output_cap_is_clamped_per_model() {
        let mut body = json!({ "model": "chat-lite", "max_tokens": 128_000 });
        clamp_max_tokens(&mut body);
        assert_eq!(body["max_tokens"], 16_384);

        let mut prefixed = json!({ "model": "NewApi/chat-pro", "max_completion_tokens": 200_000 });
        clamp_max_tokens(&mut prefixed);
        assert_eq!(prefixed["max_completion_tokens"], 65_536);
    }

    /// 没超限的不动，认不出的模型也不动（不猜上限）。
    #[test]
    fn a_reasonable_or_unknown_cap_is_left_alone() {
        let mut small = json!({ "model": "chat-pro", "max_tokens": 4096 });
        clamp_max_tokens(&mut small);
        assert_eq!(small["max_tokens"], 4096);

        let mut unknown = json!({ "model": "gpt-5", "max_tokens": 999_999 });
        clamp_max_tokens(&mut unknown);
        assert_eq!(unknown["max_tokens"], 999_999);
    }

    /// 401 带签名相关字样时，文案要指向 deviceId/installId 而不是「重新登录」。
    #[test]
    fn a_signature_failure_is_not_reported_as_an_expired_token() {
        let class = TeleagentProvider.classify(401, &json!({ "message": "invalid signature" }));
        let proto::ErrorClass::TokenExpired { message } = class else {
            panic!("401 应当归到 TokenExpired");
        };
        assert!(message.contains("签名"), "实际：{message}");
        assert!(message.contains("installId"), "实际：{message}");
    }

    /// 身份由 token 摘要生成，同 token 稳定、不同 token 不同。
    #[test]
    fn identity_is_stable_and_token_specific() {
        assert_eq!(identity_of("a.b.c"), identity_of("a.b.c"));
        assert_ne!(identity_of("a.b.c"), identity_of("x.y.z"));
        assert!(identity_of("a.b.c").starts_with("teleagent-"));
    }
}
