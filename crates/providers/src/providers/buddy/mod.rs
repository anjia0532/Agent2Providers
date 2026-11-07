//! CodeBuddy（腾讯，`copilot.tencent.com`）插件实现：**浏览器授权登录 + OpenAI 兼容转发**。
//!
//! ── 从参考实现（dsh-providers-hub）搬来时改了什么 ──────────────
//! ```text
//!   不变：OAuth 四步链路、鉴权头族、目录的三段解析、余额的双层嵌套与
//!         「只累加有效包」、签到的业务码幂等
//!   改：  ① 凭证从宿主 credential ref 改成 `ctx.store_get()`；
//!         ② 目录缓存不落盘（网关自己会缓存插件返回的清单）；
//!         ③ 账号 id 由插件生成（`buddy-<access_token 摘要>`）；
//!         ④ 成长任务体系（190KB 的 buddy-growth）**未搬** —— 见模块末的说明。
//! ```
//!
//! ── 上游的硬事实 ────────────────────────────────────────────
//! ```text
//!   1. 端点：https://copilot.tencent.com（API 域同主机）；
//!   2. 登录：POST /v2/plugin/auth/state?platform=ide → authUrl；
//!           GET  /v2/plugin/auth/token?state=…  （轮询，code 11217 = 未就绪）；
//!           GET  /v2/plugin/login/account?state=…（轮询，code 12151 = 未完成）；
//!           续期 POST /v2/plugin/auth/token/refresh（头 X-Refresh-Token）；
//!   3. 对话：POST /v2/chat/completions（OpenAI Chat，SSE）；
//!   4. 目录：GET  /v3/config（agents + models + 试用横幅）；
//!   5. 计费：POST /v2/billing/meter/{get-user-resource,checkin-activity-status,
//!                                 daily-checkin}。
//! ```
//!
//! ── 鉴权头族里的一条实测结论 ────────────────────────────────
//! `X-Conversation-{ID,Request-ID,Message-ID}` 三头**在多数账号上不是准入必需**，
//! 但在**特定账号上缺任一枚会被 400 拒**（实测 3/5 与 2/5 的分叉）。
//! ⇒ 三枚一起发。它们不是「可选的装饰」，也不是「全局必需」—— 按账号而变。
//!
//! ── 成长任务（buddy-growth）为什么没搬 ──────────────────────
//! 参考实现里它有两千多行（任务列表 / 领奖 / 盲盒 / 连续打卡 / 画布任务 /
//! 遥测上报 / 市场专家…），且与本插件协议的任务模型并不一一对应。
//! 本期先落地**每日签到**（`checkin-activity-status` + `daily-checkin`）与
//! 积分余额；成长任务体系留作独立任务，不在这一版里猜它的形状。

pub mod credits;
pub mod models;
pub mod oauth;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

use crate::http;

/// 产品配置（逆向自官方 IDE 的 product.json / headers 定义）。
pub const BUDDY: BuddyProduct = BuddyProduct {
    endpoint: "https://copilot.tencent.com",
    api_domain: "copilot.tencent.com",
    platform: "ide",
    product_code: "codebuddy",
    attribution_name: "CodeBuddy",
    client_version: "4.12.2",
    user_agent: "CodeBuddyIDE/4.12.2",
};

/// 一份产品配置（将来接国际版时平行加一个常量，实现共用）。
pub struct BuddyProduct {
    /// API 端点（含协议，不含尾斜杠）
    pub endpoint: &'static str,
    /// `X-Domain` 头的值（**必须是裸域名**，与 endpoint 一致）
    pub api_domain: &'static str,
    /// `platform` 查询参数
    pub platform: &'static str,
    /// `X-Product-Code`
    pub product_code: &'static str,
    /// `X-IDE-Name` / `X-IDE-Type` / `X-Product`（归属名，不是部署类型）
    pub attribution_name: &'static str,
    /// `X-IDE-Version` 与 User-Agent 共用
    pub client_version: &'static str,
    /// User-Agent（对齐 IDE 的 getUserAgent()）
    pub user_agent: &'static str,
}

/// 登录页会导航到的域（网关据此做导航白名单）。
pub const ALLOWED_HOSTS: &[&str] = &["copilot.tencent.com", "www.codebuddy.cn", "codebuddy.cn"];

/// CodeBuddy 适配器。
pub struct BuddyProvider;

impl Provider for BuddyProvider {
    fn meta(&self) -> ProviderMeta {
        ProviderMeta::new(ID, "CodeBuddy")
            .with_capabilities(proto::Capabilities {
                chat: true,
                // 标准 OpenAI Chat，一次请求一次回答
                stateful: false,
                // 有 refresh_token
                refresh: true,
                model_refresh: true,
                // 积分余额
                usage: true,
                // 每日签到
                checkin: true,
                claims: false,
                // 浏览器授权 + 轮询
                web_login: true,
                sse_model_rewrite: false,
                sse_strip_newline_chunks: false,
                anonymous_default_session: false,
                system_proxy_when_unset: false,
                refresh_uses_account: true,
                supports_default_model: false,
                env_credentials: false,
            })
            .with_login(vec![proto::LoginMethod::Browser {
                button: "浏览器登录".into(),
                hint: Some(
                    "打开 CodeBuddy 的授权页完成登录；授权页 5 分钟内有效，登录后会自动回到应用。"
                        .to_string(),
                ),
            }])
            // 静态兜底清单（动态拉取失败时用）
            .with_models(models::fallback_models())
            .with_account_features(proto::AccountFeatures {
                usage: true,
                identifier: vec!["id".to_string()],
                ..Default::default()
            })
            .with_checkin(proto::CheckinInfo {
                description: Some("每天替账号打一次签到，领当日积分".to_string()),
                modes: vec![proto::CheckinMode::Checkin],
                ..Default::default()
            })
    }

    fn provider_id(&self) -> String {
        ID.to_string()
    }

    // ── 转发 ──────────────────────────────────────────────────

    /// 构造 `POST {endpoint}/v2/chat/completions`（OpenAI Chat，body 原样透传）。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, &req.account)
                .await
                .map_err(|error| format!("读取 CodeBuddy 账号失败：{error}"))?;
            let (access_token, _refresh_token, domain) = credentials::tokens_of(&found.secret)?;
            // 三枚会话头：**每请求一个新 id**（官方是「会话稳定」，但实测上游
            // 不做跨轮状态机 —— 见参考实现里那段消融结论；而「缺头被 400」
            // 是真实存在的，所以照发，只是不追求与官方逐字一致）
            let conversation = new_conversation_id();
            let mut headers = vec![
                ("Authorization".to_string(), format!("Bearer {access_token}")),
                ("Accept".to_string(), "text/event-stream".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
                // X-Domain 必须与 endpoint 一致，且**不能**用凭据里那份历史快照
                (
                    "X-Domain".to_string(),
                    if domain.is_empty() {
                        BUDDY.api_domain.to_string()
                    } else {
                        domain
                    },
                ),
                (
                    "X-Product-Code".to_string(),
                    BUDDY.product_code.to_string(),
                ),
                ("X-Agent-Purpose".to_string(), "conversation".to_string()),
                ("X-IDE-Name".to_string(), BUDDY.attribution_name.to_string()),
                ("X-IDE-Type".to_string(), BUDDY.attribution_name.to_string()),
                (
                    "X-IDE-Version".to_string(),
                    BUDDY.client_version.to_string(),
                ),
                ("X-Product".to_string(), BUDDY.attribution_name.to_string()),
                ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
                (
                    "X-Conversation-ID".to_string(),
                    conversation.clone(),
                ),
                (
                    "X-Conversation-Request-ID".to_string(),
                    conversation.clone(),
                ),
                ("X-Conversation-Message-ID".to_string(), conversation),
            ];
            // 企业账号补两个头（后台「使用端」列按这组头归因）
            if let Some(enterprise_id) = credentials::enterprise_id_of(&found.secret) {
                headers.push(("X-Enterprise-Id".to_string(), enterprise_id.clone()));
                headers.push(("X-Tenant-Id".to_string(), enterprise_id));
            }
            Ok(ChatPlan::chat(
                format!("{}{}", BUDDY.endpoint, CHAT_PATH),
                headers,
                req.body,
            ))
        })
    }

    /// 上游错误分类。
    ///
    /// 代码里 `11-128`（conversation id missing）与 `11140` 都归到
    /// `TokenExpired` 这一档并不准确，但**两者都不该换号重试**——
    /// 真正需要区分的是「内容拦截」（不罚账号）与「渠道校验失败」。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let code = errors::code_of(body);
        let lowered = message.to_lowercase();
        // 内容拦截：不罚账号，换中性提示词重试
        if code == Some(11140)
            || lowered.contains("illegal api invocation")
            || lowered.contains("unapproved channel")
        {
            return proto::ErrorClass::ContentBlocked {
                status,
                message,
                upstream_code: code,
            };
        }
        if status == 401 || lowered.contains("token is required") || lowered.contains("unauthorized") {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 403 || lowered.contains("invalid signature") {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 429 || lowered.contains("rate limit") {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: code,
                status: 429,
            };
        }
        if status == 402 || lowered.contains("insufficient") || lowered.contains("quota") {
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

    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, account)
                .await
                .map_err(|error| format!("读取 CodeBuddy 账号失败：{error}"))?;
            Ok(credentials::access_token_of(&found.secret)?)
        })
    }

    fn refresh_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(ID, account)
                .await
                .map_err(|error| format!("读取 CodeBuddy 账号失败：{error}"))?;
            let (_access_token, refresh_token, domain) = credentials::tokens_of(&found.secret)?;
            let grant = oauth::refresh(ctx, &refresh_token, &domain).await?;
            let mut secret = found.secret.clone();
            if let Some(object) = secret.as_object_mut() {
                object.insert(
                    "accessToken".to_string(),
                    Value::String(grant.access_token.clone()),
                );
                object.insert(
                    "refreshToken".to_string(),
                    Value::String(grant.refresh_token.clone()),
                );
                object.insert("expiresAt".to_string(), json!(grant.expires_at));
                object.insert("domain".to_string(), Value::String(grant.domain.clone()));
            }
            // 比较再写：并发刷新时只有拿到当前值的那一方写得进去
            let _ = ctx
                .store_update(account, &found.secret, &secret)
                .await
                .map_err(|error| format!("写回 CodeBuddy 凭证失败：{error}"))?;
            Ok(grant.access_token)
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

    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let access_token = match ctx.store_get(ID, account).await {
                Ok(found) => match credentials::access_token_of(&found.secret) {
                    Ok(token) => token,
                    Err(reason) => return Ok(proto::RefreshOutcome::failed(reason)),
                },
                Err(_) if account.is_empty() => {
                    agent2api_provider_sdk::log_info!(
                        "[Models] CodeBuddy 没有可用账号，模型目录使用静态清单"
                    );
                    let count = models::fallback_models().len();
                    return Ok(proto::RefreshOutcome::refreshed(count));
                }
                Err(error) => {
                    return Ok(proto::RefreshOutcome::failed(format!(
                        "读取 CodeBuddy 账号失败：{error}"
                    )))
                }
            };
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(models::refresh(&client, &access_token, force).await)
        })
    }

    // ── 余额 / 签到 ───────────────────────────────────────────

    fn quota_sources(&self, report: &Value) -> Vec<Value> {
        crate::quota::sources(&self.meta().id, report)
    }

    fn usage<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::UsageReport> {
        Box::pin(async move {
            let access_token = self.ensure_token(ctx, account).await?;
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(credits::credit_balance(&client, &access_token).await?)
        })
    }

    fn checkin<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::CheckinReport> {
        Box::pin(async move {
            let access_token = self.ensure_token(ctx, account).await?;
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(credits::claim_daily_checkin(&client, &access_token).await?)
        })
    }

    // ── 登录 ──────────────────────────────────────────────────

    /// 申请登录态（state + authUrl）。
    fn login_start<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        _method: &str,
        _payload: &Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(async move {
            let session = oauth::start(ctx).await?;
            Ok(proto::LoginStart {
                flow: session.state.clone(),
                url: session.auth_url.clone(),
                instructions: "在打开的页面里完成 CodeBuddy 登录；授权后会自动回到应用。"
                    .to_string(),
                poll_interval_ms: 2_000,
                external_browser: false,
                allowed_hosts: ALLOWED_HOSTS.iter().map(|host| host.to_string()).collect(),
            })
        })
    }

    /// 轮询登录：先取令牌，再取账户信息。
    fn login_poll<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        flow: &str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        // flow 是 &str 入参，先取自有拷贝（异步块要跨 await 持有它）
        let flow = flow.to_string();
        Box::pin(async move {
            match oauth::poll_token(ctx, &flow).await {
                oauth::TokenPoll::Pending => Ok(proto::LoginPoll::Pending { hint: None }),
                oauth::TokenPoll::Failed(message) => Ok(proto::LoginPoll::Failed { message }),
                oauth::TokenPoll::Done(grant) => {
                    // 账户信息是登录链路的最后一步（官方也要轮询）
                    match oauth::poll_account(ctx, &flow, &grant.access_token, &grant.domain).await {
                        oauth::AccountPoll::Pending => Ok(proto::LoginPoll::Pending {
                            hint: Some("已拿到令牌，正在获取账户信息…".to_string()),
                        }),
                        oauth::AccountPoll::Failed(message) => {
                            Ok(proto::LoginPoll::Failed { message })
                        }
                        oauth::AccountPoll::Done(account) => {
                            let secret = credentials::secret_of(&grant, &account);
                            Ok(proto::LoginPoll::Done {
                                account: proto::NormalizedAccount {
                                    public: json!({
                                        "name": if account.nickname.is_empty() {
                                            format!("CodeBuddy {}", credentials::token_tail(&grant.access_token))
                                        } else {
                                            account.nickname.clone()
                                        },
                                        "uid": account.uid,
                                        "tokenTail": credentials::token_tail(&grant.access_token),
                                    }),
                                    identity: credentials::identity_of(&secret),
                                    secret,
                                    desktop: false,
                                },
                            })
                        }
                    }
                }
            }
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    /// CodeBuddy 只有浏览器登录一条入口。
    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        Box::pin(async move {
            Err("CodeBuddy 只支持浏览器登录：请点「浏览器登录」完成授权后添加账号".to_string())
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(credentials::identity_of(secret))
    }
}

/// provider id（`pack.json` 里也要写同一个）。
pub const ID: &str = "buddy";

/// 对话路径（拼在 endpoint 之后）。
pub const CHAT_PATH: &str = "/v2/chat/completions";

/// 生成一枚逐请求的会话 id（32 位无横线 hex）。
fn new_conversation_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 凭证字段读写。
pub mod credentials {
    use serde_json::Value;

    /// access_token + refresh_token + domain（一次取出，避免三次读同一份）。
    pub fn tokens_of(secret: &Value) -> Result<(String, String, String), String> {
        let access_token = text(secret, &["accessToken", "access_token"])?
            .ok_or_else(|| "CodeBuddy 账号缺少 accessToken，请重新登录".to_string())?;
        let refresh_token = text(secret, &["refreshToken", "refresh_token"])?
            .ok_or_else(|| "CodeBuddy 账号缺少 refreshToken，请重新登录".to_string())?;
        let domain = text(secret, &["domain"])?.unwrap_or_default();
        Ok((access_token, refresh_token, domain))
    }

    /// 只取 access_token。
    pub fn access_token_of(secret: &Value) -> Result<String, String> {
        text(secret, &["accessToken", "access_token"])?
            .ok_or_else(|| "CodeBuddy 账号缺少 accessToken，请重新登录".to_string())
    }

    /// 企业账号 id（个人版为空）。
    pub fn enterprise_id_of(secret: &Value) -> Option<String> {
        text(secret, &["enterpriseId", "enterprise_id"]).ok().flatten()
    }

    /// 落盘形态（含账户信息，供身份与展示复用）。
    pub fn secret_of(grant: &super::oauth::TokenGrant, account: &super::oauth::Account) -> Value {
        serde_json::json!({
            "accessToken": grant.access_token,
            "refreshToken": grant.refresh_token,
            "expiresAt": grant.expires_at,
            "refreshExpiresAt": grant.refresh_expires_at,
            "domain": grant.domain,
            "uid": account.uid,
            "nickname": account.nickname,
            "enterpriseId": account.enterprise_id,
            "accountType": account.account_type,
        })
    }

    /// 账号 id = `buddy-<access_token 摘要前 12 位>`。
    pub fn identity_of(secret: &Value) -> String {
        match text(secret, &["accessToken", "access_token"]) {
            Ok(Some(token)) => format!("buddy-{}", short_hash(&token)),
            _ => "buddy-unknown".to_string(),
        }
    }

    /// token 尾 4 字符（公开形态与默认备注名用）。
    pub fn token_tail(token: &str) -> String {
        let chars: Vec<char> = token.chars().collect();
        let start = chars.len().saturating_sub(4);
        chars[start..].iter().collect()
    }

    fn text(record: &Value, keys: &[&str]) -> Result<Option<String>, String> {
        let Some(object) = record.as_object() else {
            return Ok(None);
        };
        for key in keys {
            if let Some(value) = object.get(*key).and_then(Value::as_str) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    return Ok(Some(trimmed.to_string()));
                }
            }
        }
        Ok(None)
    }

    fn short_hash(input: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())[..12].to_string()
    }
}

/// 错误文案与业务码抽取。
mod errors {
    use serde_json::Value;

    pub fn message_of(body: &Value) -> String {
        let parts: Vec<&str> = [
            body.get("msg").and_then(Value::as_str),
            body.get("message").and_then(Value::as_str),
            body
                .get("displayMsg")
                .and_then(|value| value.get("zh"))
                .and_then(Value::as_str),
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
        body.get("code").and_then(Value::as_i64)
    }
}
