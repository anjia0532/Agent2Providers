//! OrcaRouter（`orcarouter.ai`）插件实现：**OpenAI 兼容 meta-router**。
//!
//! ── 它是什么 ────────────────────────────────────────────
//! 一把 API key 就能打到 150+ 个模型（OpenAI / Anthropic / Google / xAI /
//! DeepSeek / Qwen / Kimi / MiniMax / Z-AI …），另外还有几个**虚拟路由档**：
//!
//! | 模型 id | 是什么 |
//! |---|---|
//! | `orcarouter/free` | 免费档（issue #367 的诉求就是它 —— 绑 GitHub 账号可用） |
//! | `orcarouter/pod` | 同上，另一个池 |
//! | `orcarouter/fusion` / `-flash` / `-mini` | 融合路由，逐请求挑上游 |
//!
//! ── 上游协议 ────────────────────────────────────────────
//! ```text
//!   POST https://api.orcarouter.ai/v1/chat/completions   （OpenAI Chat，SSE）
//!   GET  https://api.orcarouter.ai/v1/models             （免鉴权，216 个模型）
//!   Authorization: Bearer <api key>
//! ```
//! 标准 OpenAI 形状，所以本家**几乎不用改写请求体** —— 唯一要做的是按模型修剪
//! 上游会拒收的采样参数（见 [`quirks`]）。
//!
//! ── ⚠️ 目录接口免鉴权 ⇒ 不能用它验 key ─────────────────────
//! `GET /v1/models` 不带 Authorization 也回 200（实测）。所以「目录刷新成功」
//! 不等于「这个 key 可用」。本插件**不做**「探活通过就落账号」的推断 —— 落账号
//! 只校验形态，key 是否真的能用要等第一次对话才知道（报 401 时文案会指路）。
//!
//! ── 归属头 ─────────────────────────────────────────────
//! 上游支持可选的 `HTTP-Referer` / `X-Title`（在它的控制台里显示调用来源）。
//! 这两项**可选**且不影响鉴权，本插件带上固定值便于用户在控制台里认出流量。

pub mod models;
pub mod quirks;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use crate::http;

/// provider id（`pack.json` 里也要写同一个）
pub const ID: &str = "orcarouter";

/// 上游基址（**含 `/v1`**，不含尾斜杠）
pub const BASE_URL: &str = "https://api.orcarouter.ai/v1";

/// 对话路径
pub const CHAT_PATH: &str = "/chat/completions";

/// 控制台里显示的调用来源（可选头 `X-Title`）
const APP_TITLE: &str = "Agent2API";

/// 控制台里显示的来源地址（可选头 `HTTP-Referer`）
const APP_URL: &str = "https://github.com/aimod-cc/Agent2API";

/// 从 secret 里取 API key。
fn api_key_of(secret: &Value) -> Result<String, String> {
    let key = ["accessToken", "apiKey", "key", "token"]
        .iter()
        .find_map(|name| secret.get(*name).and_then(Value::as_str))
        .map(str::trim)
        .unwrap_or("");
    if key.is_empty() {
        return Err("OrcaRouter 账号缺少 API Key，请重新粘贴".to_string());
    }
    Ok(key.to_string())
}

/// 形态检查：只挡「一眼不是 key」的输入（带空白的整段文本、明显过短）。
///
/// **不猜前缀**：上游的 key 格式本文档没有权威说明，编一个 `sk-` 之类的规则
/// 只会把合法 key 挡在门外。
fn shape_ok(key: &str) -> bool {
    key.len() >= 16 && !key.chars().any(char::is_whitespace)
}

/// OrcaRouter 适配器。
pub struct OrcarouterProvider;

impl Provider for OrcarouterProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "OrcaRouter")
            .with_capabilities(proto::Capabilities {
                chat: true,
                stateful: false,
                // 静态 API Key，上游没有 refresh 端点
                refresh: false,
                model_refresh: true,
                usage: false,
                checkin: false,
                claims: false,
                // 只能粘贴 key，没有可拉起的授权页
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
                label: "OrcaRouter API Key".to_string(),
                placeholder: "在 orcarouter.ai/console/keys 生成后粘贴".to_string(),
                extra_fields: Vec::new(),
            }])
            .with_models(models::list().models)
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

    /// 构造一次对话请求：OpenAI 形状原样透传，只按模型修剪上游拒收的采样参数。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, &req.account)
                .await
                .map_err(|error| format!("读取 OrcaRouter 账号失败：{error}"))?;
            let key = api_key_of(&found.secret)?;
            let mut body = req.body;
            // ⚠️ 必须在签名/摘要之前改体（本家不签名，但顺序仍按「先改体再定头」写，
            // 与别家一致，避免将来加签名时漏掉这一步）
            quirks::apply(&mut body);
            let headers = vec![
                ("Authorization".to_string(), format!("Bearer {key}")),
                ("Content-Type".to_string(), "application/json".to_string()),
                ("Accept".to_string(), "text/event-stream".to_string()),
                ("HTTP-Referer".to_string(), APP_URL.to_string()),
                ("X-Title".to_string(), APP_TITLE.to_string()),
            ];
            Ok(ChatPlan::chat(
                format!("{BASE_URL}{CHAT_PATH}"),
                headers,
                body,
            ))
        })
    }

    /// 上游错误分类。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let lowered = message.to_lowercase();
        if status == 401 || status == 403 {
            return proto::ErrorClass::TokenExpired {
                message: format!("{message}（OrcaRouter API Key 可能已失效，请在控制台重新生成）"),
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
        if status == 402 || lowered.contains("insufficient") || lowered.contains("credit") {
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
                .map_err(|error| format!("读取 OrcaRouter 账号失败：{error}"))?;
            api_key_of(&found.secret)
        })
    }

    // ── 目录 ──────────────────────────────────────────────────

    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move { Ok(models::list()) })
    }

    /// 刷新目录。
    ///
    /// 不需要账号：目录接口免鉴权（见模块头）。所以这里**不读 secret** ——
    /// 没有账号时也能把真实目录拉下来，下拉框不必退到静态兜底。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        _account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(models::refresh(&client, BASE_URL, force).await)
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            let payload = match &input.source {
                proto::NormalizeSource::Manual { payload } => payload.clone(),
                proto::NormalizeSource::FileText { content, .. } => {
                    let trimmed = content.trim();
                    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
                        parsed
                    } else {
                        json!({ "key": trimmed })
                    }
                }
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err("OrcaRouter 不支持二进制文件导入，请粘贴 API Key".to_string())
                }
                proto::NormalizeSource::Desktop => {
                    return Err(
                        "OrcaRouter 没有桌面客户端登录态可导入，请粘贴 API Key".to_string(),
                    )
                }
            };
            // `auth.methods` 申报的 `api` 方式：网关把表单字段装在 `inputs` 下
            let payload = payload
                .get("inputs")
                .filter(|inputs| inputs.is_object())
                .unwrap_or(&payload);
            let key = api_key_of(payload)?;
            if !shape_ok(&key) {
                return Err(
                    "OrcaRouter API Key 形态不对（应为不含空白的一整串，长度 ≥ 16）。请只粘贴 key 本身"
                        .to_string(),
                );
            }
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| "OrcaRouter".to_string());
            let secret = json!({ "accessToken": key, "name": name });
            Ok(proto::NormalizedAccount {
                public: json!({
                    "name": name,
                    "hasKey": true,
                    "keyTail": tail(&key),
                }),
                identity: identity_of(&key),
                secret,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(identity_of(&api_key_of(secret)?))
    }

    /// `auth.methods`：界面据此渲染「添加账号」表单（一个密钥输入框）。
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
                    "OrcaRouter 不支持管理动作「{action}」"
                ))),
            }
        })
    }
}

fn identity_of(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("orcarouter-{}", &format!("{:x}", hasher.finalize())[..12])
}

fn tail(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let start = chars.len().saturating_sub(4);
    chars[start..].iter().collect()
}

/// `auth.methods` 的返回：`type: "api"`，一个 secret 输入框。
fn login_methods() -> Value {
    json!({ "methods": [{
        "methodIndex": 0,
        "type": "api",
        "label": "OrcaRouter API Key",
        "instructions": "在 orcarouter.ai 的 Console → Keys 生成一把 API Key 后粘贴进来。免费档（orcarouter/free、orcarouter/pod）绑定 GitHub 账号即可用。",
        "prompts": [{
            "key": "key",
            "type": "text",
            "label": "API Key",
            "placeholder": "粘贴 API Key",
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
            body.pointer("/error/message").and_then(Value::as_str),
            body.get("message").and_then(Value::as_str),
            body.get("msg").and_then(Value::as_str),
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
        body.pointer("/error/code").and_then(Value::as_i64)
            .or_else(|| body.get("code").and_then(Value::as_i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_read_from_any_of_the_known_fields() {
        for field in ["accessToken", "apiKey", "key", "token"] {
            let mut secret = json!({});
            secret[field] = json!("abcdefghijklmnop1234");
            assert_eq!(api_key_of(&secret).unwrap(), "abcdefghijklmnop1234", "字段 {field} 应当被认");
        }
        assert!(api_key_of(&json!({})).is_err());
    }

    /// 形态检查只挡一眼不是 key 的输入：带空白的整段文本、明显过短。
    /// **不猜前缀** —— 编一个 `sk-` 规则会把合法 key 挡在门外。
    #[test]
    fn the_shape_check_rejects_obvious_non_keys() {
        assert!(shape_ok("abcdefghijklmnop"));
        assert!(shape_ok("or-1234567890abcdef"));
        assert!(!shape_ok("short"), "太短应当拒绝");
        assert!(!shape_ok("has space in it 1234567"), "带空白应当拒绝（多半粘了整行）");
    }

    /// 401 的文案要指路「去控制台重新生成」，而不是笼统的「凭证失效」。
    #[test]
    fn an_unauthorized_error_points_at_the_console() {
        let class = OrcarouterProvider.classify(
            401,
            &json!({ "error": { "message": "invalid api key" } }),
        );
        let proto::ErrorClass::TokenExpired { message } = class else {
            panic!("401 应当归到 TokenExpired");
        };
        assert!(message.contains("OrcaRouter"), "实际：{message}");
        assert!(message.contains("控制台"), "实际：{message}");
    }

    /// 402 与「余额不足」文案都归到额度受限（不是 Fatal，要换号）。
    #[test]
    fn insufficient_credit_is_a_quota_condition() {
        let by_status = OrcarouterProvider.classify(402, &json!({}));
        assert!(matches!(by_status, proto::ErrorClass::QuotaLimited { .. }));
        let by_text = OrcarouterProvider.classify(
            400,
            &json!({ "error": { "message": "Insufficient credit balance" } }),
        );
        assert!(matches!(by_text, proto::ErrorClass::QuotaLimited { .. }));
    }

    #[test]
    fn identity_is_stable_and_key_specific() {
        assert_eq!(identity_of("key-a-long-enough"), identity_of("key-a-long-enough"));
        assert_ne!(identity_of("key-a-long-enough"), identity_of("key-b-long-enough"));
        assert!(identity_of("key-a-long-enough").starts_with("orcarouter-"));
    }
}
