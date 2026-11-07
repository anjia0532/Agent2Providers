//! MiniMax Code（中国版 / 国际版）插件实现：**OAuth 设备码登录 + Anthropic Messages 转发**。
//!
//! ── 从参考实现（dsh-providers-hub）搬来时改了什么 ──────────────
//! ```text
//!   不变：两站配置只差 6 个字段、设备码 + PKCE 流程、令牌五条硬校验、
//!         目录的三条归一规则、签到的四条实测事实、积分的平铺响应
//!   改：  ① 凭证从宿主 credential ref 改成 `ctx.store_get()`；
//!         ② 目录缓存不落盘（网关自己会缓存插件返回的清单）；
//!         ③ 账号 id 由插件生成（`minimax-<access_token 摘要>`）；
//!         ④ 登录 flow 里带设备码会话（插件进程无状态，编进 flow 串）。
//! ```
//!
//! ── 上游的硬事实 ────────────────────────────────────────────
//! ```text
//!   1. 账号与 OAuth 主机：account.minimax.cn / account.minimax.io；
//!   2. API 主机：agent.minimax.cn / agent.minimax.io；
//!   3. 推理：POST {apiHost}/mavis/api/v1/llm/v1/messages（Anthropic Messages）；
//!   4. 目录：GET  {apiHost}/mavis/api/v1/models?region=<cn|en>&buildEnv=prod；
//!   5. 签到：GET/POST {apiHost}/minimax-cloud/api/v1/signin/{status,claim}
//!            （**必须带 `?timezone_id=`**，业务码在 `base_resp.status_code`）；
//!   6. 积分：GET  {apiHost}/minimax-cloud/api/v1/credit/details（平铺响应）。
//! ```
//!
//! ── 思考档位：三种模型三种语义（实测，别猜）──────────────────
//! | 模型 | `thinking_config.mode` | 关得掉吗 |
//! |---|---|---|
//! | M3.1-Flash-Preview | `forced_on` + 有档位表 | **关不掉**，传 `disabled` 硬 400 |
//! | M3 | `switchable` | 关得掉（不传不思考，传 `adaptive` 思考） |
//! | M2.7 / M2.7-highspeed | `forced_on`、无档位表 | 传 `disabled` 被**静默忽略** |
//!
//! ⇒ 只有 `switchable` 的模型接受「关闭思考」；`forced_on` 的一律不发 `disabled`。

pub mod credits;
pub mod models;
pub mod oauth;
pub mod region;

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ChatPlan, PluginCtx, Provider, ProviderMeta, SendFuture};
use serde_json::{json, Value};

pub use region::Region;

use crate::http;

/// OAuth scope（**凭据校验要求必须含它**，否则 `invalid_token_response`）。
pub const SCOPE: &str = "agent.default";

/// 设备码申请路径
pub const DEVICE_CODE_PATH: &str = "/oauth2/device/code";
/// 令牌路径（轮询与续期共用）
pub const TOKEN_PATH: &str = "/oauth2/token";
/// 推理路径（Anthropic Messages）
pub const INFER_PATH: &str = "/mavis/api/v1/llm/v1/messages";

/// 登录页会导航到的域（网关据此做导航白名单）。
pub const ALLOWED_HOSTS: &[&str] = &["account.minimax.cn", "account.minimax.io"];

/// 按站点参数化的适配器：**一份实现、两个实例**。
#[derive(Clone, Copy, Debug)]
pub struct MinimaxProvider {
    region: Region,
}

impl MinimaxProvider {
    /// 国内版
    pub const CN: MinimaxProvider = MinimaxProvider { region: Region::Cn };
    /// 国际版
    pub const INTL: MinimaxProvider = MinimaxProvider {
        region: Region::Intl,
    };
}

impl Provider for MinimaxProvider {
    fn meta(&self) -> ProviderMeta {
        let region = self.region;
        ProviderMeta::new(region.provider_id(), region.label())
            .with_capabilities(proto::Capabilities {
                chat: true,
                // Anthropic Messages 协议：一次请求一次回答
                stateful: false,
                // 有 refresh_token（设备码流程下发）
                refresh: true,
                model_refresh: true,
                // 积分余额
                usage: true,
                // 每日签到
                checkin: true,
                claims: false,
                // 设备码 + PKCE，拉起浏览器
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
                hint: Some(format!(
                    "打开 {} 的授权页，按页面提示完成登录；授权地址 {} 分钟内有效。",
                    region.label(),
                    "10"
                )),
            }])
            // 兜底清单（4 条，含不在客户端内置表里的 M3.1-Flash-Preview）
            .with_models(models::fallback().1)
            // 账号行：`usage` —— 积分余额；`identifier: id` —— 账号 id 由
            // access_token 的摘要拼成，没有可读的用户标识；
            // `expiry` 由 access_token 的到期时刻算（`long_lived: false`，
            // 因为上游确实会轮换 refresh_token）。
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
        self.region.provider_id().to_string()
    }

    // ── 转发 ──────────────────────────────────────────────────

    /// 构造 `POST {apiHost}/mavis/api/v1/llm/v1/messages`（Anthropic Messages）。
    ///
    /// body 由网关按 `UpstreamKind::Anthropic` 组好（system / messages /
    /// max_tokens / tools 都在里面），这里只加鉴权头。
    fn build_chat<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        req: proto::ChatRequest,
    ) -> SendFuture<'a, ChatPlan> {
        Box::pin(async move {
            let region = self.region;
            let found = ctx
                .store_get(region.provider_id(), &req.account)
                .await
                .map_err(|error| format!("读取 MiniMax 账号失败：{error}"))?;
            let access_token = credentials::access_token_of(&found.secret)?;
            Ok(ChatPlan {
                url: format!("{}{}", region.api_base_url(), INFER_PATH),
                headers: vec![
                    ("Authorization".to_string(), format!("Bearer {access_token}")),
                    ("Accept".to_string(), "text/event-stream".to_string()),
                    ("Content-Type".to_string(), "application/json".to_string()),
                ],
                body: req.body,
                upstream: proto::UpstreamKind::Anthropic,
            })
        })
    }

    /// 上游错误分类。
    ///
    /// MiniMax 的推理端点把多数业务失败放在 **HTTP 200 + 流内 error 帧**里，
    /// 所以这里的判据同时看状态码与 body 文案。
    fn classify(&self, status: u16, body: &Value) -> proto::ErrorClass {
        let message = errors::message_of(body);
        let lowered = message.to_lowercase();
        // 401 优先：与「凭据失效」逐字同形的是地理分流，但账号态的处置
        // （刷新后重试）对两种成因都成立，先按凭据失效走
        if status == 401 || lowered.contains("token is required") {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 403 || lowered.contains("invalid signature") {
            return proto::ErrorClass::TokenExpired { message };
        }
        if status == 429 || lowered.contains("rate limit") {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: errors::code_of(body),
                status: 429,
            };
        }
        if status == 402 || lowered.contains("insufficient") || lowered.contains("quota") {
            return proto::ErrorClass::QuotaLimited {
                reset_at: None,
                message,
                upstream_code: errors::code_of(body),
                status: 429,
            };
        }
        // 上下文超限：原文抛出，让宿主走溢出压缩（不罚账号）
        if status >= 400
            && (lowered.contains("context")
                || lowered.contains("too many tokens")
                || lowered.contains("max_tokens"))
        {
            return proto::ErrorClass::Fatal {
                status: 400,
                message,
                upstream_code: errors::code_of(body),
            };
        }
        proto::ErrorClass::Fatal {
            status: if status >= 500 { status } else { 502 },
            message,
            upstream_code: errors::code_of(body),
        }
    }

    /// 思考档位翻译（见模块头的表格）。
    fn reasoning_patch(
        &self,
        level: &str,
        model: &str,
        _body: &Value,
    ) -> proto::ReasoningPatch {
        let Some(entry) = models::find(self.region, model) else {
            // 目录里没有这个模型：不注入（让上游自己判）
            return proto::ReasoningPatch::Skip {
                reason: "模型不在 MiniMax 目录里，不注入思考配置".to_string(),
            };
        };
        // 关得掉思考的只有 switchable；forced_on 传 disabled 会被硬拒
        if level == "none" {
            return if entry.can_disable_thinking() {
                proto::ReasoningPatch::Set {
                    field: "thinking".to_string(),
                    value: json!({ "type": "disabled" }),
                }
            } else {
                proto::ReasoningPatch::Skip {
                    reason: format!(
                        "{} 的思考是强制开启，传 disabled 会被上游拒绝，故不注入",
                        entry.id
                    ),
                }
            };
        }
        // M3.1-Flash-Preview：必须 adaptive，档位走 output_config.effort
        if entry.requires_adaptive_thinking() {
            let effort = if entry.effort_options.iter().any(|item| item == level) {
                Some(level.to_string())
            } else {
                entry.default_effort.clone()
            };
            return match effort {
                Some(effort) => proto::ReasoningPatch::Set {
                    field: "output_config".to_string(),
                    value: json!({ "effort": effort }),
                },
                None => proto::ReasoningPatch::Set {
                    field: "thinking".to_string(),
                    value: json!({ "type": "adaptive" }),
                },
            };
        }
        // switchable 的模型：发 adaptive 就会思考
        if entry.can_disable_thinking() {
            return proto::ReasoningPatch::Set {
                field: "thinking".to_string(),
                value: json!({ "type": "adaptive" }),
            };
        }
        // 其余（forced_on 且无档位表）：不发 thinking —— 上游默认就会思考，
        // 而传 disabled 只会被静默忽略，发了反而掩盖真实行为
        proto::ReasoningPatch::Skip {
            reason: format!("{} 的思考由上游强制开启，不注入 thinking", entry.id),
        }
    }

    // ── 凭证 ──────────────────────────────────────────────────

    /// 取 access_token。
    fn ensure_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let found = ctx
                .store_get(self.region.provider_id(), account)
                .await
                .map_err(|error| format!("读取 MiniMax 账号失败：{error}"))?;
            credentials::access_token_of(&found.secret)
        })
    }

    /// 用 refresh_token 换一对新令牌（两站同一套端点）。
    fn refresh_token<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, String> {
        Box::pin(async move {
            let region = self.region;
            let found = ctx
                .store_get(region.provider_id(), account)
                .await
                .map_err(|error| format!("读取 MiniMax 账号失败：{error}"))?;
            let refresh_token = credentials::refresh_token_of(&found.secret)?;
            let grant = oauth::refresh(ctx, region, &refresh_token).await?;
            // 组装新的 secret：refresh_token 可能没被轮换，缺省沿用旧的
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
            }
            // 比较再写：并发刷新时只有拿到当前值的那一方写得进去
            let _ = ctx
                .store_update(account, &found.secret, &secret)
                .await
                .map_err(|error| format!("写回 MiniMax 凭证失败：{error}"))?;
            Ok(grant.access_token)
        })
    }

    // ── 目录 ──────────────────────────────────────────────────

    fn models<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        _account: &'a str,
    ) -> SendFuture<'a, proto::ModelList> {
        Box::pin(async move { Ok(models::list(self.region)) })
    }

    fn refresh_models<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
        force: bool,
    ) -> SendFuture<'a, proto::RefreshOutcome> {
        Box::pin(async move {
            let region = self.region;
            let access_token = match ctx.store_get(region.provider_id(), account).await {
                Ok(found) => match credentials::access_token_of(&found.secret) {
                    Ok(token) => token,
                    Err(reason) => return Ok(proto::RefreshOutcome::failed(reason)),
                },
                Err(_) if account.is_empty() => {
                    agent2api_provider_sdk::log_info!(
                        "[Models] MiniMax 没有可用账号，模型目录使用远端快照"
                    );
                    let count = models::fallback().1.len();
                    return Ok(proto::RefreshOutcome::refreshed(count));
                }
                Err(error) => {
                    return Ok(proto::RefreshOutcome::failed(format!(
                        "读取 MiniMax 账号失败：{error}"
                    )))
                }
            };
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(models::refresh(region, &client, &access_token, force).await)
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
            let region = self.region;
            let access_token = self.ensure_token(ctx, account).await?;
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(credits::credit_balance(&client, region, &access_token).await?)
        })
    }

    fn checkin<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        account: &'a str,
    ) -> SendFuture<'a, proto::CheckinReport> {
        Box::pin(async move {
            let region = self.region;
            let access_token = self.ensure_token(ctx, account).await?;
            let client = http::control_client(None, &ctx.env.proxy);
            Ok(credits::claim(&client, region, &access_token).await?)
        })
    }

    // ── 登录 ──────────────────────────────────────────────────

    /// 设备码登录：申请设备码并把会话编进 flow 串（插件进程无状态）。
    fn login_start<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        _method: &str,
        _payload: &Value,
    ) -> SendFuture<'a, proto::LoginStart> {
        Box::pin(async move {
            let region = self.region;
            let verifier = oauth::new_code_verifier();
            let auth = oauth::request_device_code(ctx, region, &verifier).await?;
            let flow = encode_flow(&auth);
            Ok(proto::LoginStart {
                flow,
                // 优先用含 user_code 的完整链接（用户点开即完成）
                url: auth.verification_uri_complete.clone(),
                instructions: format!(
                    "在打开的页面里输入授权码 {} 完成登录；授权码 {} 分钟内有效。",
                    auth.user_code,
                    "10"
                ),
                poll_interval_ms: auth.interval_ms as u64,
                external_browser: false,
                allowed_hosts: ALLOWED_HOSTS.iter().map(|host| host.to_string()).collect(),
            })
        })
    }

    /// 轮询设备码授权。
    fn login_poll<'a>(
        &'a self,
        ctx: &'a PluginCtx,
        flow: &str,
    ) -> SendFuture<'a, proto::LoginPoll> {
        // flow 的生命周期不是 'a（它是 &str 入参），而异步块要跨 await 持有它：
        // 先取一份自有拷贝，避免把入参的生命周期绑进 future
        let flow = flow.to_string();
        Box::pin(async move {
            let region = self.region;
            let Some(auth) = decode_flow(&flow) else {
                return Ok(proto::LoginPoll::Failed {
                    message: "登录流程已失效，请重新发起登录".to_string(),
                });
            };
            match oauth::poll_device_code(ctx, region, &auth).await {
                oauth::PollResult::Pending => Ok(proto::LoginPoll::Pending { hint: None }),
                oauth::PollResult::Done(grant) => {
                    let secret = credentials::secret_of(&grant);
                    Ok(proto::LoginPoll::Done {
                        account: proto::NormalizedAccount {
                            public: json!({
                                "name": region.label(),
                                "tokenTail": credentials::token_tail(&grant.access_token),
                            }),
                            identity: credentials::identity_of(&secret),
                            secret,
                            desktop: false,
                        },
                    })
                }
                oauth::PollResult::Failed(message) => {
                    Ok(proto::LoginPoll::Failed { message })
                }
            }
        })
    }

    // ── 账号 ──────────────────────────────────────────────────

    /// MiniMax 只有浏览器登录一条入口（设备码流程），没有粘贴式账号。
    fn normalize_account<'a>(
        &'a self,
        _ctx: &'a PluginCtx,
        input: proto::NormalizeInput,
    ) -> SendFuture<'a, proto::NormalizedAccount> {
        let _ = input;
        Box::pin(async move {
            Err("MiniMax Code 只支持浏览器登录：请点「浏览器登录」完成设备码授权后添加账号"
                .to_string())
        })
    }

    fn account_identity(&self, secret: &Value) -> Result<String, String> {
        Ok(credentials::identity_of(secret))
    }
}

/// 把设备码会话编进 flow 串（base64url(JSON)）。
///
/// 插件进程**无状态**：`login.start` 与 `login.poll` 是两次独立的 RPC，
/// 中间那份 `code_verifier` 必须跟着 flow 走，否则换令牌时无法通过 PKCE 校验。
fn encode_flow(auth: &oauth::DeviceAuth) -> String {
    use base64::Engine as _;
    let payload = json!({
        "deviceCode": auth.device_code,
        "codeVerifier": auth.code_verifier,
        "userCode": auth.user_code,
        "verificationUri": auth.verification_uri,
        "verificationUriComplete": auth.verification_uri_complete,
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(payload.to_string().as_bytes())
}

/// 解回设备码会话；解不出返回 `None`（调用方按「流程已失效」处理）。
fn decode_flow(flow: &str) -> Option<oauth::DeviceAuth> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(flow).ok()?;
    let payload: Value = serde_json::from_slice(&bytes).ok()?;
    Some(oauth::DeviceAuth {
        device_code: payload
            .get("deviceCode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        code_verifier: payload
            .get("codeVerifier")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        user_code: payload
            .get("userCode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        verification_uri: payload
            .get("verificationUri")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        verification_uri_complete: payload
            .get("verificationUriComplete")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        interval_ms: 5_000,
    })
}

/// 凭证字段读写（`accessToken` / `refreshToken` / `expiresAt`）。
pub mod credentials {
    use serde_json::Value;

    /// 从账号的 `secret` 里取 access_token。
    pub fn access_token_of(secret: &Value) -> Result<String, String> {
        let token = text(secret, &["accessToken", "access_token", "token"]);
        match token {
            Some(token) if !token.is_empty() => Ok(token),
            _ => Err("MiniMax 账号缺少 access_token，请重新登录".to_string()),
        }
    }

    /// 从账号的 `secret` 里取 refresh_token。
    pub fn refresh_token_of(secret: &Value) -> Result<String, String> {
        let token = text(secret, &["refreshToken", "refresh_token"]);
        match token {
            Some(token) if !token.is_empty() => Ok(token),
            _ => Err("MiniMax 账号缺少 refresh_token，请重新登录".to_string()),
        }
    }

    /// 落盘形态。
    pub fn secret_of(grant: &super::oauth::TokenGrant) -> Value {
        serde_json::json!({
            "accessToken": grant.access_token,
            "refreshToken": grant.refresh_token,
            "expiresAt": grant.expires_at,
        })
    }

    /// 账号 id = `minimax-<access_token 摘要前 12 位>`。
    ///
    /// 上游的 access_token 不是 JWT，解不出 sub；用它自己的摘要做身份，
    /// 同一账号重复添加会被网关认成同一条。
    pub fn identity_of(secret: &Value) -> String {
        match text(secret, &["accessToken", "access_token", "token"]) {
            Some(token) if !token.is_empty() => {
                format!("{}-{}", identity_prefix(secret), short_hash(&token))
            }
            _ => format!("{}-unknown", identity_prefix(secret)),
        }
    }

    /// 身份前缀按站点分开（两个 provider 的账号不会撞）。
    fn identity_prefix(secret: &Value) -> &'static str {
        match text(secret, &["region"]) {
            Some(region) if region == "minimaxintl" => "minimaxintl",
            _ => "minimax",
        }
    }

    /// token 尾 4 字符（公开形态用）。
    pub fn token_tail(token: &str) -> String {
        let chars: Vec<char> = token.chars().collect();
        let start = chars.len().saturating_sub(4);
        chars[start..].iter().collect()
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
        let candidates = [
            body.get("error").and_then(|error| error.get("message")).and_then(Value::as_str),
            body.get("message").and_then(Value::as_str),
            body.get("base_resp").and_then(|base| base.get("status_msg")).and_then(Value::as_str),
            body.get("msg").and_then(Value::as_str),
        ];
        let parts: Vec<&str> = candidates
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
        body.get("error")
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64)
            .or_else(|| body.get("code").and_then(Value::as_i64))
            .or_else(|| {
                body.get("base_resp")
                    .and_then(|base| base.get("status_code"))
                    .and_then(Value::as_i64)
            })
    }
}
