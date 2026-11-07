//! CodeBuddy 积分余额与每日签到。
//!
//! ── 端点（`/v3/config` 之外的一套计费口）──────────────────────
//! ```text
//! POST {endpoint}/v2/billing/meter/get-user-resource      积分余额
//! POST {endpoint}/v2/billing/meter/checkin-activity-status 签到活动状态
//! POST {endpoint}/v2/billing/meter/daily-checkin           领取每日签到
//! ```
//!
//! ── 三条实测事实 ────────────────────────────────────────────
//!   1. **余额响应是双层嵌套**：`data.Response.Data.Accounts[]` ——
//!      与签到端点的单层 `data` 不同，这是本接口最容易解析错的地方；
//!   2. **余额取 `CycleCapacityRemain`（本周期口径）**，不是
//!      `CapacityRemain`（终身口径）；精确值优先取带 `Precise` 后缀的
//!      字符串版本（`CapacityRemainPrecise`），整数版是截断值；
//!   3. **只累加有效包**：失效包里的额度服务端仍会返回，但不能用于扣费，
//!      并进总额会让数字虚高（实测某账号因此从 155.67 变成 655.67）。
//!
//! ── 幂等 ────────────────────────────────────────────────────
//! 重复领取是**业务码**（不是 HTTP 错误），判据是 `code`。

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;

use super::BUDDY;
use crate::http;

/// 积分余额
pub const USER_RESOURCE_PATH: &str = "/v2/billing/meter/get-user-resource";
/// 每日签到领取
pub const DAILY_CHECKIN_PATH: &str = "/v2/billing/meter/daily-checkin";

/// 已领取（幂等）
const CODE_ALREADY_CLAIMED: i64 = 2001;
/// 无领取资格
const CODE_NO_QUALIFICATION: i64 = 2002;
/// 活动已结束
const CODE_ACTIVITY_ENDED: i64 = 2003;

/// 把额度规整为两位小数。
///
/// 用 `round(v * 100) / 100` 而不是 `toFixed` 后 parse：后者对负数与极大值的
/// 行为不一致，且返回字符串会污染数值类型。
fn round_credits(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

/// 读一个数值字段，优先取带 `Precise` 后缀的精确版本。
fn precise_number(source: &Value, base_key: &str) -> Option<f64> {
    let precise = source.get(format!("{base_key}Precise"));
    if let Some(text) = precise.and_then(Value::as_str) {
        if let Ok(value) = text.parse::<f64>() {
            return Some(value);
        }
    }
    if let Some(value) = precise.and_then(Value::as_f64) {
        return Some(value);
    }
    source.get(base_key).and_then(Value::as_f64)
}

/// 服务端标记「该资源包已过期」的 Status 值（实测）。
const PACKAGE_STATUS_EXPIRED: i64 = 3;

/// 解析一个 Account 条目为一个积分包。
fn parse_package(entry: &Value) -> Option<Value> {
    let object = entry.as_object()?;
    let name = ["PackageName", "SubProductName", "PackageCode"]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
        })
        .unwrap_or("积分包");
    let unit = ["CapacityUnit", "OriginUnit"]
        .iter()
        .find_map(|key| {
            object
                .get(*key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
        })
        .unwrap_or("credit");
    let remaining = precise_number(entry, "CycleCapacityRemain")?;
    // 失效判定：Status 显式为已过期，或扣费截止已过（0/缺失 = 未下发，按未知处理）
    let status = entry.get("Status").and_then(Value::as_i64);
    let deduction_end = entry.get("DeductionEndTime").and_then(Value::as_f64).unwrap_or(0.0);
    let active = status != Some(PACKAGE_STATUS_EXPIRED)
        && (deduction_end <= 0.0 || deduction_end > http::now_ms() as f64);
    Some(json!({
        "key": name,
        "name": name,
        "unit": unit,
        "remaining": remaining,
        "total": remaining,
        "active": active,
    }))
}

/// 查积分余额（`usage` 用）。
pub async fn credit_balance(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<Value, String> {
    let url = format!("{}{}", BUDDY.endpoint, USER_RESOURCE_PATH);
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {access_token}")),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let (status, payload) = http::post_json(client, &url, &headers, &json!({}))
        .await
        .map_err(|error| format!("CodeBuddy 余额查询失败：{error}"))?;
    if status != 200 {
        return Err(format!(
            "CodeBuddy 余额查询失败（HTTP {status}）：{}",
            message(&payload)
        ));
    }
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    if code != 0 {
        return Err(format!(
            "CodeBuddy 余额查询失败（code={code}）：{}",
            message(&payload)
        ));
    }
    // 双层嵌套：data.Response.Data.Accounts[]
    let accounts = payload
        .get("data")
        .and_then(|data| data.get("Response"))
        .and_then(|response| response.get("Data"))
        .and_then(|data| data.get("Accounts"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut total = 0.0_f64;
    let mut expired_total = 0.0_f64;
    let mut packages = Vec::new();
    for entry in &accounts {
        let Some(package) = parse_package(entry) else {
            continue;
        };
        let remaining = package
            .get("remaining")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        if package.get("active").and_then(Value::as_bool).unwrap_or(false) {
            total += remaining;
        } else {
            expired_total += remaining;
        }
        packages.push(package);
    }
    Ok(json!({
        "available": round_credits(total),
        "unit": "积分",
        "credits": [{
            "key": "available", "name": "可用积分", "balance": round_credits(total),
            "unit": "积分", "snapshot": true,
        }],
        "packages": packages,
        "expiredTotal": round_credits(expired_total),
        "raw": { "accounts": accounts },
    }))
}

/// 领一次每日签到（`checkin.claim` 用）。
pub async fn claim_daily_checkin(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<proto::CheckinReport, String> {
    let url = format!("{}{}", BUDDY.endpoint, DAILY_CHECKIN_PATH);
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {access_token}")),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let (status, payload) = http::post_json(client, &url, &headers, &json!({}))
        .await
        .map_err(|error| format!("CodeBuddy 签到失败：{error}"))?;
    if status != 200 {
        return Err(format!(
            "CodeBuddy 签到失败（HTTP {status}）：{}",
            message(&payload)
        ));
    }
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(-1);
    let text = payload
        .get("msg")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string);
    // 幂等：已领取 / 无资格 / 活动结束都是非致命终态
    if code == CODE_ALREADY_CLAIMED {
        return Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Done,
            credit: None,
            streak: None,
            message: Some(text.unwrap_or_else(|| "今天已签到".to_string())),
        });
    }
    if code == CODE_NO_QUALIFICATION || code == CODE_ACTIVITY_ENDED {
        return Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Inactive,
            credit: None,
            streak: None,
            message: Some(text.unwrap_or_else(|| "当前无领取资格".to_string())),
        });
    }
    if code != 0 {
        return Err(format!(
            "CodeBuddy 签到失败（code={code}）：{}",
            text.unwrap_or_else(|| "领取失败".to_string())
        ));
    }
    let data = payload.get("data").cloned().unwrap_or(Value::Null);
    let credit = data.get("credit").and_then(Value::as_f64);
    let streak = data
        .get("streak_days")
        .and_then(Value::as_u64)
        .map(|value| value as u32);
    Ok(proto::CheckinReport {
        outcome: proto::CheckinOutcome::Claimed,
        credit: credit.map(|value| format!("{value} 积分")),
        streak,
        message: None,
    })
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
