//! TeleAgent（中国电信「星辰超级智能体」）插件实现：**云端 API + 本机签名**。
//!
//! ── 与其它家最大的不同：请求要**签名** ──────────────────────
//! 鉴权不是单纯一个 `Authorization`，而是「凭据 + 每请求现算签名」：
//!
//! ```text
//!   凭据（长期有效，两种来源）：
//!     · 本机导入 —— 运行时从桌面端数据目录读出来（见 `desktop.rs`）
//!     · 手工粘贴 —— token / deviceId / installId 三条 JSON
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
//! ── 本机导入（本家的主要登录方式）────────────────────────────
//! 桌面端把登录态存在本机（`token.json` 是 Electron safeStorage 密文，
//! `device-meta.json` 是设备指纹）。插件运行时现读现解，**不落 token** ——
//! 落库的 `secret` 只存一个 scope 引用，转发时再读一遍，这样「在客户端里
//! 重新登录后不用重启网关」才成立。详见 `desktop.rs`。
//!
//! ── 没有的能力（如实申报，不假装有）──────────────────────────
//!   · **没有续期**：凭据里没有 refresh token，上游也没有续期端点 → `refresh = false`；
//!   · **没有目录接口**：模型清单是静态 5 条（见 `models.rs`）→ `model_refresh = false`；
//!   · **积分与签到走另一个服务**（portal，见 `portal.rs`）→ `usage` / `checkin` 为真。
//!
//! ── 思维链：**独立 delta 字段**，不是正文里的标签 ─────────────
//! 2026-11 本机真实调用实测（chat-nano / chat-flash 各一次，带 tools）：
//!   · `chat-nano`      → `delta.reasoning`
//!   · `chat-flash`     → `delta.reasoning_content`
//! 正文 `delta.content` 里**没有** `<think>` 标签，`usage` 里带 `reasoning_tokens`。
//! 早期注释与部分参考实现说的「标签混在正文」已经不成立，别按标签去拆。
//!
//! 本插件走无状态透传（`build_chat`），两个字段名都会原样到客户端；网关与
//! Anthropic 转换认的是 `reasoning_content`，所以 `chat-nano` 的思考内容不会
//! 被渲染（正文、工具调用、usage 都不受影响）。要统一字段名得改走
//! `conversation()` 自己读流改写，属于独立一项工作 —— 代价是把已经实测可用的
//! 无状态链路换成一段新的流式代码，收益只是让一个模型的思考面板有内容。

pub mod desktop;
pub mod models;
pub mod portal;
pub mod sign;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use std::path::Path;

use crate::http;

/// provider id（`pack.json` 里也要写同一个）
pub const ID: &str = "teleagent";

/// 上游基址（不含尾斜杠）
pub const BASE_URL: &str = "https://agent.teleai.com.cn";

/// 对话路径（`superCowork/sapi` 两段不能省）
pub const CHAT_PATH: &str = "/superCowork/sapi/api/v1/chat/completions";

/// `X-App-Version` 与 UA 里报的客户端版本**兜底值**。
///
/// 正常路径是运行时读客户端自己的版本（`desktop::app_version`），读不到才用这里。
/// 上游自 2026-11 起加了**版本闸**：报 `2.0.0` 直接 `403 / 40301 检测到客户端
/// 版本过低`，报 `3.0.0` 正常 200（同 token、同指纹实测），所以兜底值必须跟得上。
pub const APP_VERSION: &str = "3.0.0";

/// User-Agent（照抄参考实现实测可用的那一串：把请求伪装成 opencode 客户端）
pub const USER_AGENT: &str =
    "opencode/1.2.27 ai-sdk/provider-utils/3.0.20 runtime/bun/1.3.10";

/// 一次请求要用到的条凭据（已解析成最终形态）。
struct LiveCredentials {
    token: String,
    device_id: String,
    install_id: String,
    /// 上报给上游的客户端版本（签名与 `X-App-Version` 头必须一致）。
    app_version: String,
}

/// 从账号 secret 里读三条凭据（**手工粘贴**的那种）。
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

/// 读账号 secret（给 `portal` 用；它要知道本机导入的 scope）。
pub(crate) async fn secret_of(
    ctx: &PluginCtx,
    provider: &str,
    account: &str,
) -> Result<Value, String> {
    let found = ctx
        .store_get(provider, account)
        .await
        .map_err(|error| format!("读取账号失败：{error}"))?;
    Ok(found.secret)
}

/// 解析一次请求要用的凭据：本机导入的账号**现读现解**，手工粘贴的直接用。
async fn resolve_credentials(secret: &Value) -> Result<LiveCredentials, String> {
    if secret.get("desktop").and_then(Value::as_bool).unwrap_or(false) {
        let scope = secret.get("scope").and_then(Value::as_str).unwrap_or("");
        let data =
            desktop::data_dir().ok_or_else(|| "未找到 TeleAgent 数据目录，请先安装并登录客户端".to_string())?;
        let creds = desktop::read_credentials(&data, scope)?;
        return Ok(LiveCredentials {
            token: creds.token,
            device_id: creds.device_id,
            install_id: creds.install_id,
            // 本机导入：版本号跟着客户端走，客户端升级后自动跟上
            app_version: desktop::app_version(&data),
        });
    }
    let (token, device_id, install_id) = credentials_of(secret)?;
    // 手工粘贴：允许在 secret 里钉住版本号（`appVersion`），没写就用兜底值
    let app_version = optional_field(secret, &["appVersion", "app_version"])
        .unwrap_or_else(|| APP_VERSION.to_string());
    Ok(LiveCredentials {
        token,
        device_id,
        install_id,
        app_version,
    })
}

/// 网关 apiKey 的四级解析：按家配置 → 环境变量 → 桌面端账号配置 → 安装包。
///
/// 这个 key 是**桌面端内置常量**（「预置模型」供应商的 `options.apiKey`），
/// 不是用户凭据，但同样不写进仓库 —— 运行时从用户机器上装在的那份客户端里读。
/// 四级都失败就返回空串：请求照发，上游会用 `40105` 说明问题（见 `classify`）。
///
/// 前三级都是读小文件 / 读环境变量；第四级要读一个几百 MB 的 `app.asar` 的
/// JSON 头（本机 8 MB）+ 目标文件（4 MB）—— 所以**进程内缓存一次**：路径
/// 稳定，装好客户端后进程会跟着重启。
async fn resolve_api_key(ctx: &PluginCtx, scope: Option<&str>) -> String {
    if let Ok(Value::String(value)) = ctx.settings_get(ID, "apiKey").await {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Some(value) = std::env::var("TELEAGENT_API_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return value;
    }
    if let Some(data) = desktop::data_dir() {
        let effective = match scope {
            Some(scope) if !scope.trim().is_empty() => scope.trim().to_string(),
            _ => desktop::current_scope(&data).unwrap_or_default(),
        };
        if !effective.is_empty() {
            if let Some(config) = desktop::config_dir() {
                if let Some(key) = desktop::read_api_key_from_config(&config, &effective) {
                    return key;
                }
            }
        }
    }
    static ASAR_KEY: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    ASAR_KEY
        .get_or_init(desktop::read_api_key_from_asar)
        .clone()
        .unwrap_or_default()
}

/// TeleAgent 适配器。
pub struct TeleagentProvider;

impl Provider for TeleagentProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "TeleAgent 星辰智能体")
            .with_capabilities(proto::Capabilities {
                chat: true,
                stateful: false,
                // 凭据里没有 refresh token，上游也没有续期端点
                refresh: false,
                // 没有目录接口，清单是静态的
                model_refresh: false,
                usage: true,
                checkin: true,
                claims: false,
                // 只能在客户端里登录后读取本机登录态，没有可拉起的授权页
                web_login: false,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![
                proto::LoginMethod::Desktop {
                    button: "读取本机登录态".to_string(),
                    hint: Some(
                        "读取本机 TeleAgent 桌面端的登录态（token / 设备指纹从客户端数据目录解密），不需要手工复制。仅 Windows。"
                            .to_string(),
                    ),
                },
                proto::LoginMethod::Token {
                    label: "手动粘贴三条凭据".to_string(),
                    placeholder: "粘贴 {\"token\":\"…\",\"deviceId\":\"…\",\"installId\":\"…\"}".to_string(),
                    extra_fields: Vec::new(),
                },
            ])
            .with_models(models::list())
            .with_account_features(proto::AccountFeatures {
                usage: true,
                // 本机导入的账号公开视图里带有效期（JWT 的 exp）
                identifier: vec!["accountId".to_string(), "id".to_string()],
                expiry: vec!["expiresAt".to_string()],
                ..Default::default()
            })
            .with_checkin(proto::CheckinInfo {
                description: Some(
                    "TeleAgent 每日签到 · 先查后领，已领不重复提交；积分由 portal 服务发放"
                        .to_string(),
                ),
                modes: vec![proto::CheckinMode::Checkin],
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
    /// 「`max_tokens` 封顶」与「思考档位削档」这两个改写，再签名。签名在前、
    /// 改体在后 ⇒ 上游算出的摘要对不上 ⇒ 签名失败（且报错不会告诉你差在哪一步）。
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
            let creds = resolve_credentials(&found.secret).await?;

            let mut body = req.body;
            clamp_max_tokens(&mut body);
            clamp_reasoning_effort(&mut body);
            // 目录外的 model id 在**本地**就拦下：实测上游对未知 id 不报错，而是
            // 静默回落到另一个厂商的模型（用户会拿到答非所问的结果且极难发现）。
            // 带渠道前缀的名字（`NewApi/chat-pro`）按最后一段判，所以不会被误伤。
            let asked = body.get("model").and_then(Value::as_str).unwrap_or("");
            if !models::is_known(asked) {
                return Err(format!(
                    "TeleAgent 没有模型 {asked}（可用：{}）",
                    models::MODELS
                        .iter()
                        .map(|model| model.id)
                        .collect::<Vec<_>>()
                        .join(" / ")
                ));
            }
            let payload = body.to_string();

            let app_version = creds.app_version.clone();
            let nonce = sign::new_nonce();
            let timestamp = format!("{}", http::now_ms() / 1000);
            let signed = sign::sign(
                &creds.token,
                &creds.install_id,
                &timestamp,
                &nonce,
                &app_version,
                CHAT_PATH,
                payload.as_bytes(),
            )?;

            let session = format!("ses_{}", sign::new_hex_id());
            let message = format!("msg_{}", sign::new_hex_id());
            let scope = found
                .secret
                .get("scope")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let api_key = resolve_api_key(ctx, scope).await;

            let mut headers: Vec<(String, String)> = vec![
                ("Content-Type".to_string(), "application/json".to_string()),
                ("User-Agent".to_string(), USER_AGENT.to_string()),
                ("X-App-Version".to_string(), app_version),
                ("X-Token".to_string(), creds.token.clone()),
                ("X-SuperAgent-Device-Id".to_string(), creds.device_id),
                ("X-SuperAgent-Install-Id".to_string(), creds.install_id),
                ("X-SuperAgent-Nonce".to_string(), signed.nonce.clone()),
                ("X-SuperAgent-Sign-Version".to_string(), sign::SIGN_VERSION.to_string()),
                ("X-SuperAgent-Signature".to_string(), signed.signature.clone()),
                ("X-SuperAgent-Timestamp".to_string(), signed.timestamp.clone()),
                // 下面三个是上游认的「官方客户端」特征头（参考实现实测）
                ("X-Route-Target".to_string(), "ops-gateway".to_string()),
                ("X-Teleai-Run-Unit-Type".to_string(), "agent_loop".to_string()),
                ("X-Session-Id".to_string(), session.clone()),
                ("X-Teleai-Root-Session-Id".to_string(), session),
                ("X-Message-Id".to_string(), message),
                ("Accept".to_string(), "text/event-stream".to_string()),
                // 与参考实现一致：明确要求不压缩，避免摘要/解压两个层面纠缠
                ("Accept-Encoding".to_string(), "identity".to_string()),
            ];
            // 拿不到网关 apiKey 时**不要**发一个空的 `Authorization: Bearer `
            // —— 上游会把它当成攻击特征（40105），不如干脆不发，让错误码说话
            if !api_key.is_empty() {
                headers.push(("Authorization".to_string(), format!("Bearer {api_key}")));
            }
            Ok(ChatPlan::chat(
                format!("{BASE_URL}{CHAT_PATH}"),
                headers,
                body,
            ))
        })
    }

    /// 上游错误分类。
    ///
    /// 上游把业务失败包在 HTTP 200 里、用**五位业务码**表达（`code` 字段或正文
    /// 里的一句 `40104 …`）。这些码的处置完全不同，混在一起会把「协议变了」
    /// 当成「登录失效」去重登，或把「账号被封」当成「限额」去换账号。
    ///
    /// ⚠️ **签名失败（40104）与 token 失效（40108）是两回事**：前者说明 token
    /// 是好的、只有签名不对；后者说明身份本身坏了。两者的处置完全不同。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let lowered = message.to_lowercase();
        let code = errors::code_of(body).or_else(|| errors::code_in_message(&message));

        if let Some(code) = code {
            match code {
                // 签名无效：token 是好的，重登没用，别让用户白折腾
                40104 => {
                    return proto::ErrorClass::Fatal {
                        status: 401,
                        message: format!(
                            "{message}（**签名无效**：token 本身是好的，是签名对不上 —— 一般是上游协议变了，或请求路径少了 /superCowork/sapi；不要反复重新登录）"
                        ),
                        upstream_code: Some(code),
                    };
                }
                // 网关 apiKey 没带上：本机客户端版本不受支持
                40105 => {
                    return proto::ErrorClass::Fatal {
                        status: 401,
                        message: format!(
                            "{message}（**网关 apiKey 缺失**：本机 TeleAgent 版本不受支持，或安装包结构变了；可设环境变量 TELEAGENT_API_KEY 显式指定）"
                        ),
                        upstream_code: Some(code),
                    };
                }
                // token 无效 / 过期：真正的登录失效
                40108 => {
                    return proto::ErrorClass::TokenExpired {
                        message: format!(
                            "{message}（登录态已失效：请在 TeleAgent 桌面端重新登录，然后重新读取本机登录态）"
                        ),
                    };
                }
                // 客户端版本闸：跟登录态无关，重登只会白折腾
                40301 => {
                    return proto::ErrorClass::Fatal {
                        status: 403,
                        message: format!(
                            "{message}（**不是登录失效**：上游有最低客户端版本要求，当前上报 {APP_VERSION}；升级 TeleAgent 后重新导入，或在账号 secret 里加 appVersion 覆盖）"
                        ),
                        upstream_code: Some(code),
                    };
                }
                // 封禁 / 停用：封的是模型调用通道，重登解决不了
                40109 | 40110 => {
                    return proto::ErrorClass::Fatal {
                        status: 403,
                        message: format!(
                            "{message}（账号{}：封的是**模型调用通道**，积分仍可读；重新登录解决不了，请换账号或联系天翼 AI 客服）",
                            if code == 40109 { "已被封禁" } else { "已停用" }
                        ),
                        upstream_code: Some(code),
                    };
                }
                // 积分不足
                402 | 4029 => {
                    return proto::ErrorClass::QuotaLimited {
                        reset_at: None,
                        message,
                        upstream_code: Some(code),
                        status: 402,
                    };
                }
                // 频率过高
                429 | 4290 => {
                    return proto::ErrorClass::QuotaLimited {
                        reset_at: None,
                        message,
                        upstream_code: Some(code),
                        status: 429,
                    };
                }                // 请求体过大：不是账号问题
                413 => {
                    return proto::ErrorClass::Fatal {
                        status: 413,
                        message: format!("{message}（请求体过大：减少工具或附件，不是账号问题）"),
                        upstream_code: Some(code),
                    };
                }
                // 内容类型不支持（如给不支持图片的模型发了图）
                1210 => {
                    return proto::ErrorClass::Fatal {
                        status: 400,
                        message: format!(
                            "{message}（内容类型不支持：换 chat-pro / chat-flash 发图片，或去掉图片）"
                        ),
                        upstream_code: Some(code),
                    };
                }
                _ => {}
            }
        }

        if status == 401 || status == 403 {
            let hint = if lowered.contains("版本") || lowered.contains("version") {
                "（这是**客户端版本闸**，不是登录失效：别重登，把上报的客户端版本调上去即可）"
            } else if lowered.contains("sign")
                || lowered.contains("signature")
                || lowered.contains("签名")
            {
                "（看起来是**签名**失败而不是 token 失效：请核对 deviceId / installId 是否与 token 同一台设备）"
            } else {
                "（登录态可能已失效，请在 TeleAgent 桌面端重新登录后重新读取本机登录态）"
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
            resolve_credentials(&found.secret).await.map(|creds| creds.token)
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

    /// 三条路都收：本机导入（`Desktop` 来源 / 动态表单 methodIndex 0）、
    /// 手工粘贴（`Manual` / 文件，methodIndex 1）。
    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            // 本机导入：来源是 Desktop，或动态表单的「读取本机登录态」那一条
            let local_scope = match &input.source {
                proto::NormalizeSource::Desktop => Some(String::new()),
                proto::NormalizeSource::Manual { payload } => {
                    if payload.get("methodIndex").and_then(Value::as_i64) == Some(0) {
                        let scope = payload
                            .get("inputs")
                            .and_then(|inputs| inputs.get("scope"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        Some(scope.to_string())
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(scope) = local_scope {
                return import_local(scope).await;
            }

            // 一条粘贴文本（文件导入，或新表单的 `paste` 字段）
            let pasted = match &input.source {
                proto::NormalizeSource::FileText { content, .. } => content.trim().to_string(),
                proto::NormalizeSource::Manual { payload } => payload
                    .get("inputs")
                    .and_then(|inputs| inputs.get("paste"))
                    .or_else(|| payload.get("paste"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
                proto::NormalizeSource::FileBase64 { .. } => {
                    return Err(
                        "TeleAgent 不支持二进制文件导入，请粘贴登录态文本".to_string()
                    )
                }
                proto::NormalizeSource::Desktop => {
                    // 上面已经处理过，这里只是穷举
                    return Err("TeleAgent 本机导入处理失败".to_string());
                }
            };
            // `auth.methods` 申报的 `api` 方式：网关把表单字段装在 `inputs` 下
            let payload = match &input.source {
                proto::NormalizeSource::Manual { payload } => payload
                    .get("inputs")
                    .filter(|inputs| inputs.is_object())
                    .cloned()
                    .unwrap_or_else(|| payload.clone()),
                _ => Value::Null,
            };
            let local = desktop::data_dir();
            let (mut token, mut device_id, mut install_id) = if pasted.is_empty() {
                // 旧表单：token / deviceId / installId 三个字段
                (
                    optional_field(&payload, &["token", "accessToken", "access_token"])
                        .unwrap_or_default(),
                    optional_field(&payload, &["deviceId", "device_id"]).unwrap_or_default(),
                    optional_field(&payload, &["installId", "install_id"]).unwrap_or_default(),
                )
            } else {
                parse_pasted_login(&pasted, local.as_deref())?
            };
            // 手填的设备指纹优先于粘贴 / 本机读到的
            if let Some(value) = optional_field(&payload, &["deviceId", "device_id"]) {
                device_id = value;
            }
            if let Some(value) = optional_field(&payload, &["installId", "install_id"]) {
                install_id = value;
            }
            if device_id.is_empty() || install_id.is_empty() {
                if let Some((meta_device, meta_install)) =
                    local.as_deref().and_then(desktop::read_device_meta)
                {
                    if device_id.is_empty() {
                        device_id = meta_device;
                    }
                    if install_id.is_empty() {
                        install_id = meta_install;
                    }
                }
            }
            if token.is_empty() {
                return Err("没有读到 TeleAgent 的 token：请粘贴登录态（token.json 全文或 token 串）".to_string());
            }
            sign::jwt_third_segment(&token)?;
            for (value, name) in [(&device_id, "deviceId"), (&install_id, "installId")] {
                if value.is_empty() {
                    return Err(format!(
                        "缺少 {name}：本机没有 TeleAgent 的 device-meta.json，请在「{name}（可选）」输入框里手填 —— 这两个值必须与 token 来自同一台设备"
                    ));
                }
            }
            let name = payload
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| "TeleAgent".to_string());
            let expires_at = jwt_expiry_ms(&token);
            // 版本闸：允许调用方显式给 appVersion（Linux 网关上没客户端，读不到）
            let app_version = optional_field(&payload, &["appVersion", "app_version"])
                .unwrap_or_else(|| APP_VERSION.to_string());
            let secret = json!({
                "token": token,
                "deviceId": device_id,
                "installId": install_id,
                "name": name,
                "appVersion": app_version,
            });
            let mut public = json!({
                "name": name,
                "hasToken": true,
                "tokenTail": tail(&token),
                "deviceId": device_id,
            });
            if let (Some(object), Some(expires)) = (public.as_object_mut(), expires_at) {
                object.insert("expiresAt".to_string(), Value::from(expires));
            }
            Ok(proto::NormalizedAccount {
                public,
                identity: identity_of(&token),
                secret,
                desktop: false,
            })
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        if secret.get("desktop").and_then(Value::as_bool).unwrap_or(false) {
            let scope = secret.get("scope").and_then(Value::as_str).unwrap_or("");
            return Ok(identity_of_scope(scope));
        }
        let token = credentials_of(secret)?.0;
        Ok(identity_of(&token))
    }

    fn account_view(&self, secret: &Value) -> Result<Value, String> {
        if secret.get("desktop").and_then(Value::as_bool).unwrap_or(false) {
            let name = secret
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or("TeleAgent");
            let account_id = secret.get("accountId").and_then(Value::as_str);
            let expires_at = secret.get("expiresAt").and_then(Value::as_i64);
            let mut public = json!({
                "name": name,
                "hasToken": true,
                // 本机引用不落 token，也就没有 tail 可显示
                "tokenTail": "",
                "desktop": true,
            });
            if let Some(object) = public.as_object_mut() {
                if let Some(id) = account_id {
                    object.insert("accountId".to_string(), Value::String(id.to_string()));
                }
                if let Some(expires) = expires_at {
                    object.insert("expiresAt".to_string(), Value::from(expires));
                }
            }
            return Ok(public);
        }
        let (token, device_id, _install_id) = credentials_of(secret)?;
        let name = secret
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or("TeleAgent");
        let mut public = json!({
            "name": name,
            "hasToken": true,
            "tokenTail": tail(&token),
            "deviceId": device_id,
        });
        if let (Some(object), Some(expires)) = (public.as_object_mut(), jwt_expiry_ms(&token)) {
            object.insert("expiresAt".to_string(), Value::from(expires));
        }
        Ok(public)
    }

    // ── 余额 / 签到 ───────────────────────────────────────────

    fn usage<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::UsageReport> {
        Box::pin(async move { portal::query_usage(ctx, account).await })
    }

    fn checkin<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::CheckinReport> {
        Box::pin(async move { portal::claim_daily(ctx, account).await })
    }

    // ── 管理面 ────────────────────────────────────────────────

    /// `auth.methods`：界面据此渲染「添加账号」表单。
    ///
    /// 两条路：`methodIndex 0` = 本机导入（下拉选账号），`methodIndex 1` = 手工
    /// 粘贴三条凭据。**必须保留动态方式**：旧版 `with_login` 声明（含 Desktop）
    /// 在插件架构下不会下发到界面，只有 `auth.methods` 这条通道能露出本机导入。
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

/// 本机导入一条账号（现读现解，落库只留 scope 引用）。
async fn import_local(scope: String) -> Result<proto::NormalizedAccount, String> {
    let data = desktop::data_dir()
        .ok_or_else(|| "未找到 TeleAgent 数据目录，请先安装 TeleAgent 桌面版并登录".to_string())?;
    let scope = if scope.trim().is_empty() || scope.trim() == "__none__" {
        // `__none__` 是登录下拉框在「本机没找到账号」时给的占位值
        desktop::current_scope(&data)
            .map_err(|_| "未找到本机登录的 TeleAgent 账号：请先安装并登录 TeleAgent 桌面版".to_string())?
    } else {
        scope.trim().to_string()
    };
    let creds = desktop::read_credentials(&data, &scope)?;
    let name = creds
        .account_name
        .clone()
        .or_else(|| creds.account_id.clone())
        .unwrap_or_else(|| "TeleAgent".to_string());
    let expires_at = creds.expires_at.map(|seconds| seconds * 1000);
    let secret = json!({
        "desktop": true,
        "scope": creds.scope,
        "name": name,
        "accountId": creds.account_id,
        "expiresAt": expires_at,
    });
    let mut public = json!({
        "name": name,
        "hasToken": true,
        "tokenTail": "",
        "deviceId": creds.device_id,
        "desktop": true,
    });
    if let Some(object) = public.as_object_mut() {
        if let Some(id) = &creds.account_id {
            object.insert("accountId".to_string(), Value::String(id.clone()));
        }
        if let Some(expires) = expires_at {
            object.insert("expiresAt".to_string(), Value::from(expires));
        }
    }
    Ok(proto::NormalizedAccount {
        public,
        identity: identity_of_scope(&creds.scope),
        secret,
        desktop: true,
    })
}

/// 本机账号的稳定身份：优先 accountId，否则用 scope。
///
/// **不能**用 token 摘要 —— 本机导入的 token 会被桌面端重新登录替换，用它做
/// 身份会每次换一个账号出来。
fn identity_of_scope(scope: &str) -> String {
    let user_id = portal::user_id_of_scope(scope);
    if !user_id.is_empty() {
        return format!("teleagent-{user_id}");
    }
    format!("teleagent-{scope}")
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

/// 上游认的思考档位（由弱到强）。
const ACCEPTED_EFFORTS: [&str; 3] = ["low", "high", "max"];

/// 「关闭思考」的各种写法 —— 上游一律拒绝。
const OFF_EFFORTS: [&str; 7] = ["off", "none", "disabled", "false", "no", "0", ""];

/// 把任意档位取值映射成上游认的档位；`None` 表示**应删掉这个字段**。
///
/// 上游只认 `low` / `high` / `max`，且**没有「关闭思考」这个概念**：
/// 带上 `off` 那类写法会直接 400（原话「该模型始终思考，不支持关闭思考；
/// 请使用 low、high 或 max」）。删掉字段即「按模型默认思考」，是唯一合法的表达。
fn normalize_effort(level: &str) -> Option<&'static str> {
    let value = level.trim().to_lowercase();
    if OFF_EFFORTS.contains(&value.as_str()) {
        return None;
    }
    if ACCEPTED_EFFORTS.contains(&value.as_str()) {
        return Some(match value.as_str() {
            "low" => "low",
            "high" => "high",
            _ => "max",
        });
    }
    match value.as_str() {
        "minimal" => Some("low"),
        // 就近落档：宁可多思考，也不要因为一个不认识的档位整轮失败
        "medium" | "xhigh" => Some("high"),
        _ => Some("high"),
    }
}

/// 削掉上游不认的思考字段（`reasoning_effort` / `reasoningEffort` /
/// `enable_thinking` / `thinking`）。
///
/// 只碰思考相关的键，`messages` / `tools` / `temperature` / `max_tokens`
/// 一个字节都不动。正文里没有思考字段时**直接返回**，不做任何改写。
fn clamp_reasoning_effort(body: &mut Value) {
    const KEYS: [&str; 4] =
        ["reasoning_effort", "reasoningEffort", "enable_thinking", "thinking"];
    let Some(object) = body.as_object_mut() else {
        return;
    };
    if !KEYS.iter().any(|key| object.contains_key(*key)) {
        return;
    }
    let raw = ["reasoning_effort", "reasoningEffort"]
        .iter()
        .find(|key| object.contains_key(**key))
        .and_then(|key| object.get(*key));
    let normalized = match raw {
        Some(Value::String(text)) => normalize_effort(text),
        // 非字符串（对象 / 数字）与「只有 thinking 键」都归为删除
        _ => None,
    };
    for key in KEYS {
        object.remove(key);
    }
    if let Some(level) = normalized {
        object.insert("reasoning_effort".to_string(), json!(level));
    }
}

/// 取一个非空字符串字段（多个候选键名依次看）。
fn optional_field(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// 从一条粘贴文本里认出登录态（token 必有，设备指纹尽量带）。
///
/// 收四种写法，覆盖用户手上真实能拿到的东西：
///   1. `<tenant>:<JWT>` —— 桌面端密文解出来就是这个，也是上游 `X-Token` 的原形；
///   2. 纯 JWT；
///   3. `token.json` 全文（`encryptedToken`）—— 同机可用本机密钥解，异机不行；
///   4. `{"token":…,"deviceId":…,"installId":…}` 旧格式。
///
/// 「没有 deviceId / installId」不当错误：调用方会从本机 `device-meta.json` 补，
/// 补不到再让用户手填。
fn parse_pasted_login(
    text: &str,
    data: Option<&Path>,
) -> Result<(String, String, String), String> {
    let raw = text.trim().trim_matches('"').trim();
    if raw.is_empty() {
        return Err("粘贴内容为空：请把 token.json 全文或 token 串粘进来".to_string());
    }
    if raw.starts_with('{') {
        let value: Value = serde_json::from_str(raw).map_err(|_| {
            "粘贴的 JSON 解析失败：请整段复制 token.json，或直接粘 token 串".to_string()
        })?;
        let value = value
            .get("inputs")
            .filter(|inputs| inputs.is_object())
            .unwrap_or(&value);
        if let Some(encrypted) = optional_field(value, &["encryptedToken", "encrypted_token"]) {
            let data = data.ok_or_else(|| {
                "这台机器上没有 TeleAgent 数据目录：token.json 里的密文只能用本机密钥解，请改粘 token 串"
                    .to_string()
            })?;
            let plain = desktop::decrypt_safe_storage(data, &encrypted)?;
            let token = plain.trim().to_string();
            if token.is_empty() {
                return Err("token.json 解出来是空的：请确认文件没被截断".to_string());
            }
            return Ok((token, String::new(), String::new()));
        }
        let token = optional_field(value, &["token", "accessToken", "access_token"])
            .ok_or_else(|| {
                "粘贴的 JSON 里没有 token 字段：只接受 token.json 或 {\"token\":…} 两种形状"
                    .to_string()
            })?;
        return Ok((
            token,
            optional_field(value, &["deviceId", "device_id"]).unwrap_or_default(),
            optional_field(value, &["installId", "install_id"]).unwrap_or_default(),
        ));
    }
    // 纯文本：`<tenant>:<JWT>` 或 JWT
    let token = raw.to_string();
    let jwt = match token.rsplit_once(':') {
        Some((_, rest)) => rest,
        None => token.as_str(),
    };
    if jwt.split('.').count() != 3 {
        return Err(
            "没能从粘贴内容里认出 token：应当是三段点分的 JWT，或 <tenant>:<JWT> 整串"
                .to_string(),
        );
    }
    Ok((token, String::new(), String::new()))
}

/// JWT 的 `exp`（毫秒）。解不出来就返回 `None`，不编造有效期。
fn jwt_expiry_ms(token: &str) -> Option<i64> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("exp")?.as_i64().map(|seconds| seconds * 1000)
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

/// `auth.methods` 的返回：两条 `api` 方式（本机导入 + 手工粘贴）。
fn login_methods() -> Value {
    let scopes = desktop::data_dir().map(|data| desktop::list_scopes(&data)).unwrap_or_default();
    let options: Vec<Value> = if scopes.is_empty() {
        vec![json!({ "value": "__none__", "label": "（未找到本机登录的 TeleAgent 账号）" })]
    } else {
        scopes
            .iter()
            .map(|scope| {
                let label = desktop::data_dir()
                    .and_then(|data| desktop::read_credentials(&data, scope).ok())
                    .and_then(|creds| creds.account_name)
                    .unwrap_or_else(|| scope.clone());
                json!({ "value": scope, "label": label })
            })
            .collect()
    };
    json!({ "methods": [
        {
            "methodIndex": 0,
            "type": "api",
            "label": "读取本机 TeleAgent 登录态",
            "instructions": "从本机 TeleAgent 桌面端读取登录态（token 与设备指纹从客户端数据目录解密），不需要手工复制。仅 Windows；客户端需已登录。",
            "prompts": [
                { "key": "scope", "type": "select", "label": "选择账号", "options": options, "optional": false }
            ],
            "localOnly": false,
            "manualCallback": false,
            "callbackInput": "url",
            "embeddedOnly": false
        },
        {
            "methodIndex": 1,
            "type": "api",
            "label": "粘贴登录态",
            "instructions": "把登录态粘进来即可：token.json 全文、<tenant>:<JWT>、或纯 JWT 都认。deviceId / installId 本机有 device-meta.json 就自动补，没有才需要手填（两个值必须与 token 同一台设备）。",
            "prompts": [
                { "key": "paste", "type": "text", "label": "登录态", "placeholder": "粘贴 token.json 内容，或 Em9xR4:eyJ… 整串", "secret": true, "optional": false },
                { "key": "deviceId", "type": "text", "label": "deviceId（可选）", "placeholder": "留空则读本机 device-meta.json", "secret": false, "optional": true },
                { "key": "installId", "type": "text", "label": "installId（可选）", "placeholder": "留空则读本机 device-meta.json", "secret": false, "optional": true }
            ],
            "localOnly": false,
            "manualCallback": false,
            "callbackInput": "url",
            "embeddedOnly": false
        }
    ] })
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
        [body.get("code"), body.pointer("/error/code"), body.pointer("/data/code")]
            .into_iter()
            .flatten()
            .find_map(as_i64)
    }

    /// 正文里那句 `40104 invalid signature` 里的五位码。
    ///
    /// 上游有时把业务码只写在正文里（没有 `code` 字段），漏掉这一层会把
    /// 「签名无效」当成普通 401 去重登。
    pub fn code_in_message(message: &str) -> Option<i64> {
        let bytes = message.as_bytes();
        let mut index = 0;
        while index + 5 <= bytes.len() {
            let window = &bytes[index..index + 5];
            if window.iter().all(|byte| byte.is_ascii_digit()) {
                // 前后都不能还是数字（避免把长数字里的一段当码）
                let before_ok = index == 0 || !bytes[index - 1].is_ascii_digit();
                let after = index + 5;
                let after_ok = after >= bytes.len() || !bytes[after].is_ascii_digit();
                if before_ok && after_ok {
                    if let Ok(code) = message[index..after].parse::<i64>() {
                        return Some(code);
                    }
                }
            }
            index += 1;
        }
        None
    }

    fn as_i64(value: &Value) -> Option<i64> {
        if let Some(code) = value.as_i64() {
            return Some(code);
        }
        value.as_str()?.trim().parse::<i64>().ok()
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

    #[test]
    fn effort_levels_are_mapped_to_what_upstream_accepts() {
        assert_eq!(normalize_effort("low"), Some("low"));
        assert_eq!(normalize_effort("high"), Some("high"));
        assert_eq!(normalize_effort("max"), Some("max"));
        // 就近落档
        assert_eq!(normalize_effort("minimal"), Some("low"));
        assert_eq!(normalize_effort("medium"), Some("high"));
        assert_eq!(normalize_effort("xhigh"), Some("high"));
        // 关闭类写法一律删掉
        assert_eq!(normalize_effort("off"), None);
        assert_eq!(normalize_effort("none"), None);
        assert_eq!(normalize_effort("disabled"), None);
        assert_eq!(normalize_effort(""), None);
        // 不认识的档位：兜到 high，而不是整轮 400
        assert_eq!(normalize_effort("whatever"), Some("high"));
    }

    /// `medium` 被削成 `high`，`off` 被删掉，`messages` 不动。
    #[test]
    fn an_unsupported_effort_is_clamped_before_sending() {
        let mut body = json!({
            "model": "chat-pro",
            "reasoning_effort": "medium",
            "messages": [{ "role": "user", "content": "hi" }],
        });
        clamp_reasoning_effort(&mut body);
        assert_eq!(body["reasoning_effort"], "high");
        assert_eq!(body["messages"][0]["content"], "hi");

        let mut off = json!({ "model": "chat-pro", "reasoning_effort": "off" });
        clamp_reasoning_effort(&mut off);
        assert!(off.get("reasoning_effort").is_none(), "关闭类写法必须删掉");

        let mut thinking = json!({ "model": "chat-pro", "thinking": { "type": "disabled" } });
        clamp_reasoning_effort(&mut thinking);
        assert!(thinking.get("thinking").is_none());

        let mut clean = json!({ "model": "chat-pro", "messages": [] });
        clamp_reasoning_effort(&mut clean);
        assert_eq!(clean, json!({ "model": "chat-pro", "messages": [] }), "没有思考字段就不动");
    }

    /// 签名失败与 token 失效必须分开说（否则用户会一直去重新登录）。
    #[test]
    fn signature_failure_and_expired_token_are_distinguished() {
        let signature = TeleagentProvider.classify(401, &json!({ "message": "invalid signature" }));
        let proto::ErrorClass::TokenExpired { message } = signature else {
            panic!("401 应当归到 TokenExpired");
        };
        assert!(message.contains("签名"), "实际：{message}");

        let banned = TeleagentProvider.classify(200, &json!({ "code": 40109, "msg": "current user is banned" }));
        let proto::ErrorClass::Fatal { message, .. } = banned else {
            panic!("封禁应当归到 Fatal");
        };
        assert!(message.contains("封禁"), "实际：{message}");
    }

    /// 版本闸（403 / 40301）不能被说成「登录失效」—— 用户会白重登一遍。
    #[test]
    fn a_client_version_gate_is_not_a_login_failure() {
        let gated = TeleagentProvider.classify(
            403,
            &json!({ "code": 40301, "message": "检测到客户端版本过低，请检查新版本并升级以继续使用" }),
        );
        let proto::ErrorClass::Fatal { message, .. } = gated else {
            panic!("版本闸应当归到 Fatal");
        };
        assert!(message.contains("不是登录失效"), "实际：{message}");
        assert!(message.contains(APP_VERSION), "要说出当前上报的版本：{message}");

        // 上游只给文案、不给业务码时，也不能再劝用户重登
        let plain = TeleagentProvider.classify(403, &json!({ "message": "检测到客户端版本过低" }));
        let proto::ErrorClass::TokenExpired { message } = plain else {
            panic!("无码时沿用原分类");
        };
        assert!(message.contains("版本闸"), "实际：{message}");
    }

    /// 业务码只在正文里时也要认出来（上游有时不回 `code` 字段）。
    #[test]
    fn a_business_code_inside_the_message_is_recognized() {
        assert_eq!(errors::code_in_message("40104 invalid signature"), Some(40104));
        assert_eq!(errors::code_in_message("code 40109 current user is banned"), Some(40109));
        // 长数字里的一段不算
        assert_eq!(errors::code_in_message("trace 1234567890"), None);
        assert_eq!(errors::code_in_message("no code here"), None);
    }

    /// 身份：手工粘贴的按 token 摘要，本机导入的按 accountId/scope。
    #[test]
    fn identity_is_stable_per_source() {
        assert_eq!(identity_of("a.b.c"), identity_of("a.b.c"));
        assert_ne!(identity_of("a.b.c"), identity_of("x.y.z"));
        assert!(identity_of("a.b.c").starts_with("teleagent-"));
        assert_eq!(
            identity_of_scope("v1_public_2119666955975630848"),
            "teleagent-2119666955975630848"
        );
        assert_eq!(identity_of_scope("weird"), "teleagent-weird");
    }

    /// 登录方式：本机导入那条必须带上下拉选项，否则界面上是个不能提交的空表单。
    #[test]
    fn login_methods_offers_local_import_and_manual_paste() {
        let value = login_methods();
        let methods = value["methods"].as_array().expect("两条登录方式");
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0]["methodIndex"], 0);
        assert_eq!(methods[0]["type"], "api");
        assert!(methods[0]["prompts"][0]["options"].as_array().is_some());
        assert_eq!(methods[1]["methodIndex"], 1);
        // 一条粘贴 + 两个可选手填的设备指纹
        assert_eq!(methods[1]["prompts"][0]["key"], "paste");
        assert_eq!(methods[1]["prompts"][0]["optional"], false);
        assert_eq!(methods[1]["prompts"][1]["key"], "deviceId");
        assert_eq!(methods[1]["prompts"][1]["optional"], true);
        assert_eq!(methods[1]["prompts"][2]["optional"], true);
    }

    /// 粘贴的三种形态都要认：`tenant:JWT` / 纯 JWT / 旧的三条 JSON。
    #[test]
    fn a_pasted_login_is_recognized_in_every_shape() {
        let (token, device, install) =
            parse_pasted_login("Em9xR4:aaa.bbb.ccc", None).expect("tenant 前缀整串");
        assert_eq!(
            token, "Em9xR4:aaa.bbb.ccc",
            "前缀要原样保留（X-Token 与签名都用整串）"
        );
        assert!(
            device.is_empty() && install.is_empty(),
            "粘贴里没带设备指纹时交给调用方补，不当错误"
        );

        let (token, _, _) = parse_pasted_login("  \"aaa.bbb.ccc\"  ", None).expect("纯 JWT");
        assert_eq!(token, "aaa.bbb.ccc");

        let json = r#"{"token":"aaa.bbb.ccc","deviceId":"d1","installId":"i1"}"#;
        let (token, device, install) = parse_pasted_login(json, None).expect("旧的三条 JSON");
        assert_eq!(
            (token.as_str(), device.as_str(), install.as_str()),
            ("aaa.bbb.ccc", "d1", "i1")
        );
    }

    /// 认不出来要报得具体，而不是留一个空 token 去换一个笼统的 401。
    #[test]
    fn an_unrecognized_paste_is_named() {
        let message = parse_pasted_login("hello world", None).expect_err("不是 JWT 应当报错");
        assert!(message.contains("JWT"), "实际：{message}");

        let empty = parse_pasted_login("   ", None).expect_err("空内容应当报错");
        assert!(empty.contains("为空"), "实际：{empty}");

        let wrong_json = parse_pasted_login(r#"{"hello":1}"#, None).expect_err("没有 token 应当报错");
        assert!(wrong_json.contains("token"), "实际：{wrong_json}");
    }

    /// 有效期从 JWT 的 `exp` 读；读不到就不编一个。
    #[test]
    fn expiry_comes_from_the_jwt_claim() {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"exp":1765000000}"#);
        let token = format!("aaa.{payload}.bbb");
        assert_eq!(jwt_expiry_ms(&token), Some(1_765_000_000_000));
        assert_eq!(jwt_expiry_ms("aaa.bbb.ccc"), None);
    }
}
