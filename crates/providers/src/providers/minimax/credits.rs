//! MiniMax 积分余额与每日签到。
//!
//! ── 三个端点（两站同形，只差主机）────────────────────────────
//! ```text
//! GET  {apiHost}/minimax-cloud/api/v1/signin/status?timezone_id=<IANA>
//! POST {apiHost}/minimax-cloud/api/v1/signin/claim?timezone_id=<IANA>   body {}
//! GET  {apiHost}/minimax-cloud/api/v1/credit/details
//! ```
//!
//! ── 四条实测事实（改动前先读完）──────────────────────────────
//! 1. **`timezone_id` 是 query 参数且必填**：实测四种组合里 query 生效、
//!    请求头无效、都不带报 `invalid timezone_id`、非法时区名也报错；
//! 2. **业务码在 `base_resp.status_code`**（不是 `code`），且
//!    `invalid timezone_id` 也是 **HTTP 200** —— 只看 HTTP 状态码会把它
//!    当成成功；
//! 3. **两个端点的响应形状不同，不能一刀切**：
//!    `signin/*` 是**信封**（业务字段在 `data` 下），
//!    `credit/details` 是**平铺的**（`details` / `total_count` 与 `base_resp`
//!    同级，**没有** `data` 键）。只认 `data` 会把一个合法响应判成
//!    「响应缺少 data 字段」，于是「余额为 0」被报成查询失败；
//! 4. **幂等判据是 `claim_result`**（`1` = 本次真领取，`2` = 已领过），
//!    **不是 HTTP 状态码**（重复领取同样 200）。

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;

use super::region::Region;
use crate::http;

/// 签到领取路径（**必须带 `?timezone_id=`**）
pub const SIGNIN_CLAIM_PATH: &str = "/minimax-cloud/api/v1/signin/claim";
/// 积分明细路径（平铺响应）
pub const CREDIT_DETAILS_PATH: &str = "/minimax-cloud/api/v1/credit/details";

/// 默认时区（IANA）。
///
/// 上游按它划分「今日」的签到窗口。这里取北京时间 —— 与绝大多数用户的
/// 实际使用窗口一致；上游接受任意合法 IANA 名，将来要按账号配置时替换它。
pub const DEFAULT_TIMEZONE: &str = "Asia/Shanghai";

/// `claim_result` 的取值：`1` = 本次真领取，`2` = 已领过。
const CLAIM_RESULT_CLAIMED: i64 = 1;
const CLAIM_RESULT_ALREADY: i64 = 2;

/// 一次信封请求的结果。
///
/// 业务码在 `base_resp.status_code`，且失败也可能是 HTTP 200 ——
/// 所以这里把「HTTP 成功」与「业务成功」分开判。
struct Envelope {
    ok: bool,
    message: String,
    data: Value,
}

/// 拆一次响应：先看 HTTP，再看 `base_resp.status_code`。
fn parse_envelope(status: u16, payload: &Value) -> Envelope {
    let base = payload.get("base_resp");
    let business_code = base
        .and_then(|value| value.get("status_code"))
        .and_then(Value::as_i64);
    let detail = base
        .and_then(|value| value.get("status_msg"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let http_ok = (200..300).contains(&status);
    let business_ok = business_code.unwrap_or(0) == 0;
    let message = detail
        .map(str::to_string)
        .or_else(|| {
            payload
                .get("message")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("上游返回 HTTP {status}"));
    Envelope {
        ok: http_ok && business_ok,
        message,
        data: payload.clone(),
    }
}

/// 取业务载荷：`signin/*` 在 `data` 下，`credit/details` 是平铺的。
fn business_data(payload: &Value) -> Value {
    match payload.get("data") {
        Some(Value::Object(_)) => payload.get("data").cloned().unwrap_or(Value::Null),
        _ => payload.clone(),
    }
}

/// 领一次每日签到（`checkin.claim` 用）。
pub async fn claim(
    client: &reqwest::Client,
    region: Region,
    access_token: &str,
) -> Result<proto::CheckinReport, String> {
    let url = format!(
        "{}{}?timezone_id={}",
        region.api_base_url(),
        SIGNIN_CLAIM_PATH,
        DEFAULT_TIMEZONE
    );
    let headers = vec![("Authorization".to_string(), format!("Bearer {access_token}"))];
    let (status, payload) = http::post_json(client, &url, &headers, &json!({})).await?;
    let envelope = parse_envelope(status, &payload);
    if !envelope.ok {
        return Err(envelope.message);
    }
    let data = business_data(&envelope.data);
    let claim_result = data.get("claim_result").and_then(Value::as_i64);
    let points = data
        .get("points")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    match claim_result {
        // 幂等：重复领取返回 2（AlreadyClaimed），**不是** HTTP 错误
        Some(CLAIM_RESULT_ALREADY) => Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Done,
            credit: None,
            streak: None,
            message: Some("今日已签到".to_string()),
        }),
        Some(CLAIM_RESULT_CLAIMED) => {
            let streak = data
                .get("panel")
                .and_then(|panel| panel.get("continue_signin_days"))
                .and_then(Value::as_u64)
                .map(|value| value as u32);
            Ok(proto::CheckinReport {
                outcome: proto::CheckinOutcome::Claimed,
                credit: Some(format!("{points} 积分")),
                streak,
                message: None,
            })
        }
        _ => Err("MiniMax 签到响应缺少有效的 claim_result，请稍后重试".to_string()),
    }
}

/// 查积分余额（`usage` 用）。
///
/// 余额 = 各积分包 `remaining_amount` 之和；每条明细就是一个独立的「积分包」，
/// 到期时刻 = `expire_at_ms`（**毫秒**时间戳，直接透传，不做时区换算）。
pub async fn credit_balance(
    client: &reqwest::Client,
    region: Region,
    access_token: &str,
) -> Result<Value, String> {
    let url = format!("{}{}", region.api_base_url(), CREDIT_DETAILS_PATH);
    let headers = vec![("Authorization".to_string(), format!("Bearer {access_token}"))];
    let (status, payload) = http::get_json(client, &url, &headers).await?;
    let envelope = parse_envelope(status, &payload);
    if !envelope.ok {
        return Err(envelope.message);
    }
    // 平铺响应：`details` / `total_count` 与 `base_resp` 同级
    let data = business_data(&envelope.data);
    let details = data.get("details").and_then(Value::as_array).cloned();
    if details.is_none() && data.get("total_count").is_none() {
        return Err("MiniMax 余额响应形状不符合预期（服务端可能改版）".to_string());
    }
    let mut total = 0.0_f64;
    let mut packages = Vec::new();
    if let Some(rows) = details {
        for row in rows {
            let Some(object) = row.as_object() else { continue };
            let Some(remaining) = object
                .get("remaining_amount")
                .and_then(Value::as_f64)
            else {
                continue;
            };
            total += remaining;
            // 到期时刻：解析不出就**不写**（= 未知，分档落永久桶），绝不填 0
            let expire_at = object
                .get("expire_at_ms")
                .and_then(Value::as_i64)
                .filter(|value| *value > 0);
            let granted_at = object.get("granted_at_ms").and_then(Value::as_i64);
            packages.push(json!({
                "key": granted_at.map(|ms| ms.to_string()).unwrap_or_else(|| "credit".to_string()),
                "name": granted_at
                    .and_then(crate::beijing::date_key_of_ms)
                    .unwrap_or_else(|| "积分包".to_string()),
                "unit": "credit",
                "remaining": remaining,
                "total": remaining,
                "active": true,
                "expireAtMs": expire_at,
            }));
        }
    }
    Ok(json!({
        "available": total,
        "unit": "积分",
        "credits": [{
            "key": "available", "name": "可用积分", "balance": total,
            "unit": "积分", "snapshot": true,
        }],
        "packages": packages,
        "raw": { "details": data },
    }))
}
