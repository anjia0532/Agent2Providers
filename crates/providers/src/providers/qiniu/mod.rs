//! 七牛云（`api.qnaigc.com`）插件实现：**无状态 OpenAI 兼容转发 + 粘贴式 API Key**。
//!
//! ── 从参考实现（dsh-providers-hub）搬来时改了什么 ──────────────
//! ```text
//!   不变：OpenAI 兼容端点、`sk-` 前缀的静态 Key、无 refresh、无余额端点、
//!         错误分类的优先级顺序、目录快照兜底表
//!   改：  ① 凭证从宿主 credential ref 改成 `ctx.store_get()`；
//!         ② 目录缓存不落盘（网关自己会缓存插件返回的清单）；
//!         ③ 账号 id 由插件生成（`qiniu-<key 摘要前 12 位>`），网关按
//!            `identity` 去重；
//!         ④ 工具包装不做 —— DSH 那次事故是它自己的扁平工具形状，本网关
//!            下行就是标准 OpenAI Chat 格式（`type:'function'` 已就位）。
//! ```
//!
//! ── 上游的硬事实 ────────────────────────────────────────────
//! ```text
//!   1. 端点：https://api.qnaigc.com/v1（OpenAI 兼容）；
//!   2. 鉴权：Authorization: Bearer <API Key>（Key 以 sk- 开头、长期有效）；
//!   3. chat：POST /chat/completions（SSE 流式）；
//!   4. 目录：GET /models —— **免鉴权也回 200**，所以「目录能读到」
//!      不能用来判凭据有效性；
//!   5. 模型 id 由平台动态下发，**带命名空间前缀与裸名两种形态混合**，
//!      必须逐字透传（官方 FAQ 要求与模型广场的 API model 参数一致）；
//!   6. 没有 refresh / 余额 / 签到端点。
//! ```
//!
//! ── 本家没有的东西（如实声明，别照抄别家）──────────────────────
//!   - **没有续期**：静态 API Key，上游没有 refresh 接口 → `refresh = false`；
//!   - **没有网页登录**：粘贴式凭证，不开窗口（`web_login` 默认 false）；
//!   - **不做签到**：没有可自动领的奖励活动（`checkin = false`）；
//!   - **不做余额查询**：余额只在登录后的网页控制台可见（`usage = false`）。

pub mod credentials;
pub mod errors;
pub mod models;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use crate::http;

/// provider id（`pack.json` 里也要写同一个）
pub const ID: &str = "qiniu";

/// OpenAI 兼容 base URL，**含 `/v1`**，不带尾斜杠。
pub const BASE_URL: &str = "https://api.qnaigc.com/v1";

/// API Key 前缀（官方明示）。
pub const KEY_PREFIX: &str = "sk-";

/// 七牛云适配器
pub struct QiniuProvider;

impl Provider for QiniuProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "七牛云")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 标准 OpenAI 协议，一次请求一次回答
                stateful: false,
                // 静态 Key，上游没有 refresh 接口
                refresh: false,
                model_refresh: true,
                // 无余额端点（余额只在网页控制台可见）
                usage: false,
                // 没有可自动领的奖励活动
                checkin: false,
                claims: false,
                // 粘贴式凭证，不开窗口
                web_login: false,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: false,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![proto::LoginMethod::Token {
                label: "API Key".into(),
                placeholder: "粘贴 sk- 开头的 API Key".into(),
                extra_fields: vec![],
            }])
            // 兜底清单 = 远端实测快照（**非空**）：冷缓存即空会让面板把整个
            // provider 误显示为「已关闭且无模型可关」，见 `models.rs` 模块头
            .with_models(models::fallback_models())
            // 账号行：
            //   `usage: false` —— 本家没有余额查询（与 `Capabilities::usage` 同口径）；
            //   `identifier: id` —— 没有可读的用户标识：账号 id 由 key 的
            //     SHA-256 前 12 位拼成（`qiniu-<hash>`），标识列显示这个 id
            //     本身，与 commandcode 同一处置；
            //   `expiry` 空 + `long_lived: true` —— 静态 Key，上游没有到期时刻。
            .with_account_features(proto::AccountFeatures {
                identifier: vec!["id".to_string()],
                long_lived: true,
                ..Default::default()
            })
    }

    fn provider_id(&self) -> String {
        ID.to_string()
    }

    // ── 无状态转发 ────────────────────────────────────────────

    /// 构造 `POST {BASE_URL}/chat/completions`（标准 OpenAI 协议，body 原样透传）。
    ///
    /// 模型 id **原样发**（含 `组织/模型名` 形态）：官方 FAQ 明确要求请求里的
    /// `model` 与模型广场的「API model 参数」逐字一致，拆分或归一就是把它改坏。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let account = ctx
                .store_get(ID, &req.account)
                .await
                .map_err(|error| format!("读取七牛云账号失败：{error}"))?;
            let api_key = credentials::api_key_of(&account.secret)?;
            let headers = vec![
                // 网关的发送层会自动补 Content-Type；这里只加鉴权与 Accept
                ("Authorization".to_string(), format!("Bearer {api_key}")),
                ("Accept".to_string(), "text/event-stream".to_string()),
            ];
            Ok(ChatPlan::chat(
                format!("{BASE_URL}/chat/completions"),
                headers,
                req.body,
            ))
        })
    }

    /// 上游错误分类（顺序即优先级，见 `errors.rs` 的模块头）。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        errors::classify(status, body)
    }

    // ── 凭证 ──────────────────────────────────────────────────

    /// 取可用 API Key。本家**没有续期**：这里只做「记录里有没有 key」的检查，
    /// 上游拒了就是 401，网关把它归成 `TokenExpired`。
    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, account)
                .await
                .map_err(|error| format!("读取七牛云账号失败：{error}"))?;
            credentials::api_key_of(&found.secret)
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

    /// 刷模型目录：用指定账号（空串 = 本家第一个可用账号）的 Key。
    ///
    /// 「一个账号都没有」不是失败 —— 那是「用户还没添加账号」的正常状态。
    /// 但插件侧拿不到「网关有没有账号」这个事实，而手里有一份可用的快照，
    /// 所以直接用快照刷新（与 commandcode 的处置一致）：界面总能看到模型。
    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let api_key = match ctx.store_get(ID, account).await {
                Ok(found) => match credentials::api_key_of(&found.secret) {
                    Ok(key) => key,
                    // 账号存在但凭证坏了：如实报失败（不是「没有账号」）
                    Err(reason) => return Ok(proto::RefreshOutcome::failed(reason)),
                },
                Err(_) if account.is_empty() => {
                    agent2api_provider_sdk::log_info!(
                        "[Models] 七牛云没有可用账号，模型目录使用远端快照"
                    );
                    let count = models::fallback_models().len();
                    return Ok(proto::RefreshOutcome::refreshed(count));
                }
                Err(error) => {
                    return Ok(proto::RefreshOutcome::failed(format!(
                        "读取七牛云账号失败：{error}"
                    )))
                }
            };
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(models::refresh(&client, &api_key, force).await)
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    /// 规范化一条账号：粘贴归一化（剥引号 / 整行前缀 / 尾部杂字段）+ 形态检查
    /// + best-effort 探活。
    ///
    /// ── 校验顺序（先本地、再线上）是刻意的 ──────────────────────
    /// 本地形态不对时**一次网络都不发**（用户粘错了东西，探活没有意义）；
    /// 线上探活失败**不阻断添加**（见 [`credentials::shape_ok`] 与探活的三档语义）。
    fn normalize_account<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            let (raw, name) = match &input.source {
                proto::NormalizeSource::Manual { payload } => {
                    let raw = credentials::api_key_from_payload(payload);
                    let name = payload
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string);
                    (raw, name)
                }
                proto::NormalizeSource::FileText { content, .. } => {
                    // 文件可能是裸 key，也可能是 `{"apiKey": "sk-..."}`
                    let trimmed = content.trim();
                    if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
                        (credentials::api_key_from_payload(&parsed), None)
                    } else {
                        (trimmed.to_string(), None)
                    }
                }
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err("七牛云不支持二进制文件导入，请粘贴 API Key".to_string());
                }
                proto::NormalizeSource::Desktop => {
                    return Err(
                        "七牛云不支持导入桌面端登录态，请粘贴 API Key（sk- 开头）添加账号"
                            .to_string(),
                    );
                }
            };
            let api_key = normalize_key(&raw);
            if api_key.is_empty() {
                return Err(format!("请粘贴七牛云的 API Key（{KEY_PREFIX} 开头）"));
            }
            if raw.chars().count() > 8192 {
                return Err("粘贴的内容过长，请确认复制的是 API Key 本身".to_string());
            }
            if !credentials::shape_ok(&api_key) {
                return Err(format!(
                    "这不是七牛云的 API Key：应以 {KEY_PREFIX} 开头、只含字母数字与 _ -；\
                     请在七牛云控制台重新复制"
                ));
            }
            // best-effort 探活：/models 免鉴权也回 200，所以只有明确的
            // 401/403 才判无效；其余（含网络抖动）一律放行
            let client = http::control_client(input.proxy.as_ref(), &ctx.env.proxy);
            let headers = vec![("Authorization".to_string(), format!("Bearer {api_key}"))];
            if let Ok((status, _)) = http::get_json(&client, &format!("{BASE_URL}/models"), &headers).await
            {
                if status == 401 || status == 403 {
                    return Err(format!(
                        "七牛云 API Key 无效或已失效（HTTP {status}）：请在控制台重新获取后粘贴"
                    ));
                }
            }
            // 稳定身份 = key 的摘要前缀（上游没有 userId 可解析）
            let identity = format!("qiniu-{}", short_hash(&api_key));
            let display = input
                .name
                .clone()
                .or(name)
                .unwrap_or_else(|| format!("七牛云 {}", credentials::key_tail(&api_key)));
            Ok(proto::NormalizedAccount {
                secret: json!({ "apiKey": api_key }),
                public: json!({
                    "name": display,
                    "tokenTail": credentials::key_tail(&api_key),
                }),
                identity,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        let api_key = credentials::api_key_of(secret)?;
        Ok(format!("qiniu-{}", short_hash(&api_key)))
    }
}

/// 粘贴归一化：剥引号 / 整行前缀 / 尾部杂字段，返回**裸 key**。
///
/// 做法是**扫描 `sk-` 并取其后连续合法字符**（正则 `sk-[a-zA-Z0-9_-]+` 的
/// 手写形态）—— 这一步同时完成前缀剥离与尾部截断。扫不到 `sk-` 时只剥引号
/// 与空白，交给形态检查给出可读的报错。
fn normalize_key(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\'' | '`' | ',' | ';'))
        .trim();
    if let Some(key) = extract_key(trimmed) {
        return key;
    }
    // 没有 `sk-` 形态：仍把空白剥掉（key 里不含空白）
    trimmed.chars().filter(|ch| !ch.is_whitespace()).collect()
}

/// 扫描第一个 `sk-` 并取其后连续合法字符
fn extract_key(text: &str) -> Option<String> {
    let start = text.find(KEY_PREFIX)?;
    let rest = &text[start + KEY_PREFIX.len()..];
    let body: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '-')
        .collect();
    if body.is_empty() {
        return None;
    }
    Some(format!("{KEY_PREFIX}{body}"))
}

/// key 的短摘要（16 位 hex，用于账号 id；不可反推）
fn short_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())[..16].to_string()
}
