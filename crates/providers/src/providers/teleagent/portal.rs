//! TeleAgent「积分福利社」portal：积分余额查询与每日签到。
//!
//! ── 与聊天网关是**两个服务** ──────────────────────────────────
//! 聊天走 `https://agent.teleai.com.cn/superCowork/sapi`，要两步 HMAC 签名；
//! 积分走的是 `…/meter/super-agent/user/portal`，鉴权是 **cookie + 请求头**，
//! 不签名。两者互不影响：封禁后聊天全 401，积分照样能读能领（参考实现实测）。
//!
//! ── cookie 从哪来 ────────────────────────────────────────────
//! 桌面端把每个账号的 cookie 存在独立分区的 Chromium cookie 库里：
//! ```text
//! %USERPROFILE%\.local\share\TeleAgent\Partitions\owner%3A<scope>\Network\Cookies
//! ```
//! 该实例把值**明文存在 `value` 列**（`encrypted_value` 为空），所以通常不需要
//! 解密；万一上游改成加密存储，这里用 `Local State` 的 os_crypt 密钥解一次
//! （与 `desktop::decrypt_safe_storage` 同一条链），仍读不到就返回「积分不可用」
//! —— **不静默返回错误余额**。
//!
//! ── 一条必须知道的实测限制（Windows）──────────────────────────
//! 桌面端**运行时会独占 cookie 库**：本机实测（客户端 3.0.0）`CreateFile`
//! 带任何 share mode 都拿不到句柄，复制也一样。所以客户端开着的时候读不到
//! cookie，积分与签到会如实报「读不到积分凭据」，而不是给一个假余额。
//! 关掉客户端（或它自己退出）之后即可读取。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic = "abort"`：本文件零 unwrap / expect / panic。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::PluginCtx;

use super::{desktop, ID};

/// portal 服务根地址（**注意不是聊天网关**）。
pub const PORTAL_BASE: &str = "https://agent.teleai.com.cn/meter/super-agent/user/portal";

/// 只取 portal 需要的两个 cookie。
const COOKIE_SQL: &str =
    "SELECT name, value, encrypted_value FROM cookies WHERE name IN ('operationToken','operToken')";

/// portal 凭据（cookie + 账号 id）。
#[derive(Clone, Debug)]
pub struct PortalAuth {
    /// 账号 id（账号目录名 `v1_public_<userId>` 的尾段）。
    pub user_id: String,
    /// `operationToken`（同时用作 `X-Token` 头）。
    pub operation_token: String,
    /// `operToken`（只进 Cookie 头）。
    pub oper_token: String,
}

/// 账号目录名 → userId。
///
/// 与参考实现同一口径：`v<digits>_public_<digits>` 直接取尾段；否则取最后一个
/// `_` 之后的部分，**纯数字才认**（不猜）。
pub fn user_id_of_scope(scope: &str) -> String {
    let parts: Vec<&str> = scope.split('_').collect();
    if parts.len() >= 3 && parts[0].len() > 1 && parts[0].starts_with('v') && parts[1] == "public" {
        let tail = parts[parts.len() - 1];
        if !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_digit()) {
            return tail.to_string();
        }
    }
    String::new()
}

/// 读一个账号的 portal 凭据；读不到返回 `None`（调用方据此降级）。
pub fn read_portal_auth(scope: &str) -> Option<PortalAuth> {
    let data = desktop::data_dir()?;
    let user_id = user_id_of_scope(scope);
    if user_id.is_empty() {
        return None;
    }
    // 分区目录名有两种写法（`owner%3A` 是 `owner:` 的转义），两种都试
    let mut candidates: Vec<PathBuf> = Vec::new();
    for owner in [format!("owner%3A{scope}"), format!("owner:{scope}")] {
        candidates.push(data.join("Partitions").join(owner).join("Network").join("Cookies"));
    }
    for db in candidates {
        let Some(cookies) = read_cookie_db(&db) else {
            continue;
        };
        let operation_token = cookies.get("operationToken")?;
        if operation_token.is_empty() {
            return None;
        }
        return Some(PortalAuth {
            user_id,
            operation_token: operation_token.clone(),
            oper_token: cookies.get("operToken").cloned().unwrap_or_default(),
        });
    }
    None
}

/// 读 cookie 库：先试直接只读打开，失败再复制一份读（客户端运行时会锁原库）。
fn read_cookie_db(db: &Path) -> Option<HashMap<String, String>> {
    if !db.is_file() {
        return None;
    }
    if let Some(cookies) = read_cookie_copy(db) {
        return Some(cookies);
    }
    let copy = copy_db(db)?;
    let result = read_cookie_copy(&copy);
    if let Some(dir) = copy.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}

/// 复制库文件（连同 journal / wal / shm）到临时目录。
fn copy_db(source: &Path) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("teleagent-cookies-{}", crate::ids::uuid_v4()));
    std::fs::create_dir_all(&dir).ok()?;
    let target = dir.join("Cookies");
    std::fs::copy(source, &target).ok()?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let from = PathBuf::from(format!("{}{suffix}", source.display()));
        if from.is_file() {
            let to = PathBuf::from(format!("{}{suffix}", target.display()));
            let _ = std::fs::copy(from, to);
        }
    }
    Some(target)
}

/// 只读打开一份 cookie 库并取两个 cookie。
///
/// `no such table: cookies` 属于**正常空状态**（库未初始化 / 快照不完整 /
/// 该分区从未登录），返回空表而不是错误。
fn read_cookie_copy(path: &Path) -> Option<HashMap<String, String>> {
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let mut stmt = match conn.prepare(COOKIE_SQL) {
        Ok(stmt) => stmt,
        Err(error) => {
            // 空库 / 未初始化：静默当「没有 cookie」
            if error.to_string().contains("no such table") {
                return Some(HashMap::new());
            }
            return None;
        }
    };
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).unwrap_or_default(),
                row.get::<_, Vec<u8>>(2).unwrap_or_default(),
            ))
        })
        .ok()?;
    let data_dir = desktop::data_dir();
    let mut cookies: HashMap<String, String> = HashMap::new();
    for row in rows.flatten() {
        let (name, plain, encrypted) = row;
        if !plain.is_empty() {
            cookies.insert(name, plain);
            continue;
        }
        // 加密存储时用 os_crypt 密钥解一次（与 desktop 解密同一条链）
        if let Some(data) = &data_dir {
            if let Ok(key) = crate::crypto::os_crypt_aes_key(&data.join("Local State")) {
                if let Ok(value) = crate::crypto::decrypt_os_crypt_blob(&encrypted, &key) {
                    if let Ok(text) = String::from_utf8(value) {
                        if !text.is_empty() {
                            cookies.insert(name, text);
                        }
                    }
                }
            }
        }
    }
    Some(cookies)
}

/// 发一次带鉴权的 GET，返回 `data` 节点。
async fn portal_get(auth: &PortalAuth, path: &str, query: &[(&str, &str)]) -> Result<Value, String> {
    let mut url = format!("{PORTAL_BASE}{path}");
    if !query.is_empty() {
        let params: Vec<String> = query
            .iter()
            .map(|(key, value)| format!("{key}={}", encode_query(value)))
            .collect();
        url.push('?');
        url.push_str(&params.join("&"));
    }
    let cookie = format!("operToken={}; operationToken={}", auth.oper_token, auth.operation_token);
    let headers = vec![
        ("X-Token".to_string(), auth.operation_token.clone()),
        ("userId".to_string(), auth.user_id.clone()),
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), "Mozilla/5.0 TeleAgent".to_string()),
        ("Referer".to_string(), "https://agent.teleai.com.cn/teleagent-space".to_string()),
        ("Cookie".to_string(), cookie),
    ];
    let response = crate::http::send_raw("GET", &url, None, &headers, None, Some(15_000))
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "TeleAgent 积分接口超时".to_string()
            } else {
                format!("TeleAgent 积分接口请求失败：{error}")
            }
        })?;
    if response.status == 401 || response.status == 403 {
        return Err(format!(
            "TeleAgent 积分凭据已失效（HTTP {}），请在桌面端重新登录后重试",
            response.status
        ));
    }
    if !response.ok {
        return Err(format!("TeleAgent 积分接口返回 HTTP {}", response.status));
    }
    let payload = response.payload.ok_or_else(|| "TeleAgent 积分接口响应不是 JSON".to_string())?;
    // portal 的业务码：`code != 200` 也是失败
    let code = payload.get("code").and_then(Value::as_i64);
    if let Some(code) = code {
        if code != 200 {
            let message = payload
                .get("msg")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .unwrap_or("上游未返回错误详情");
            return Err(format!("TeleAgent 积分接口失败（code={code}）：{message}"));
        }
    }
    Ok(payload.get("data").cloned().unwrap_or(Value::Null))
}

/// 最小 query 编码：只转义必然破坏 URL 的字符。
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("%26"),
            '=' => out.push_str("%3D"),
            '+' => out.push_str("%2B"),
            '#' => out.push_str("%23"),
            ' ' => out.push_str("%20"),
            other => out.push(other),
        }
    }
    out
}

/// 账号 secret → scope（本机导入的账号才有）。
pub fn scope_of(secret: &Value) -> Option<String> {
    if !secret.get("desktop").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    secret
        .get("scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// 读积分余额 + 套餐名，归成界面认的形状。
///
/// 契约见网关 `ProviderAdapter::query_usage`：`available` **只在真读到数**时写
/// （写成 0 会被限制器当成「余额为 0」）。读不到 cookie / 接口失败时返回 `Err`，
/// 由调用方显示成失败行。
pub async fn query_usage(ctx: &PluginCtx, account: &str) -> Result<Value, String> {
    let secret = super::secret_of(ctx, ID, account).await?;
    let scope = scope_of(&secret).ok_or_else(|| {
        "这个账号不是本机导入的，没有积分凭据；请在 TeleAgent 桌面端登录后重新导入".to_string()
    })?;
    let auth = read_portal_auth(&scope).ok_or_else(|| {
        "读不到积分凭据（cookie）：TeleAgent 客户端开着时会锁住 cookie 库，请关闭客户端后重试；或在桌面端重新登录".to_string()
    })?;
    let points = portal_get(&auth, "/points/detail", &[]).await?;
    let center = portal_get(&auth, "/companyStore/userCenter", &[]).await.unwrap_or(Value::Null);

    let balance = points
        .get("pointsBalance")
        .and_then(|value| value.as_f64().or_else(|| value.as_str().and_then(|text| text.trim().parse::<f64>().ok())));
    // 最早到期的活动余额（没有就不写 —— 界面按键是否存在判断）
    let expires_at = soonest_expiry(&points);
    let plan_name = center
        .get("plan_display_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty());

    let mut wallets = Vec::new();
    if let Some(balance) = balance {
        let mut wallet = json!({
            "type": "points_balance",
            "displayName": "积分余额",
            "balance": balance,
        });
        if let Some(expires) = &expires_at {
            if let Some(object) = wallet.as_object_mut() {
                object.insert("expiresAt".to_string(), Value::String(expires.clone()));
            }
        }
        wallets.push(wallet);
    }

    let mut shaped = json!({
        "unit": "积分",
        "wallets": wallets,
        "raw": { "points": points, "center": center },
    });
    if let Some(balance) = balance {
        if let Some(object) = shaped.as_object_mut() {
            object.insert("available".to_string(), Value::from(balance));
        }
    }
    if let Some(plan) = plan_name {
        if let Some(object) = shaped.as_object_mut() {
            object.insert("subscription".to_string(), json!({ "planName": plan }));
        }
    }
    Ok(shaped)
}

/// 从 `groups[].active[].effectiveEnd` 里找最早到期的那个。
fn soonest_expiry(points: &Value) -> Option<String> {
    let groups = points.get("groups")?.as_array()?;
    let mut soonest: Option<String> = None;
    for group in groups {
        let active = group.get("active")?.as_array()?;
        for item in active {
            let end = item.get("effectiveEnd")?.as_str()?.trim().to_string();
            if end.is_empty() {
                continue;
            }
            if soonest.as_ref().is_none_or(|current| end < *current) {
                soonest = Some(end);
            }
        }
    }
    soonest
}

/// 每日签到（幂等：先查状态，已领就直接返回，**不碰领取接口**）。
pub async fn claim_daily(ctx: &PluginCtx, account: &str) -> Result<proto::CheckinReport, String> {
    let secret = super::secret_of(ctx, ID, account).await?;
    let scope = scope_of(&secret).ok_or_else(|| {
        "这个账号不是本机导入的，没有积分凭据；请在 TeleAgent 桌面端登录后重新导入".to_string()
    })?;
    let auth = read_portal_auth(&scope).ok_or_else(|| {
        "读不到积分凭据（cookie）：TeleAgent 客户端开着时会锁住 cookie 库，请关闭客户端后重试；或在桌面端重新登录".to_string()
    })?;

    let before = portal_get(&auth, "/companyStore/v2/checkDayTask", &[]).await?;
    let task = before.get("daily_task").cloned().unwrap_or(Value::Null);
    if task.get("claimed_today").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Done,
            credit: None,
            streak: None,
            message: Some("今天已经签过了".to_string()),
        });
    }
    // 活动未开放（`visible != true`）是中性状态，不是失败
    if !task.get("visible").and_then(Value::as_bool).unwrap_or(true) {
        return Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Inactive,
            credit: None,
            streak: None,
            message: Some("当前没有签到活动".to_string()),
        });
    }
    let claimable = task
        .get("daily_claimable_points")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);

    portal_get(&auth, "/companyStore/checkTask", &[("type", "daily_login")]).await?;

    // 复查一次：领取接口 2xx 但实际没发的情况要如实报失败
    let after = portal_get(&auth, "/companyStore/v2/checkDayTask", &[])
        .await
        .unwrap_or(Value::Null);
    let claimed = after
        .get("daily_task")
        .and_then(|task| task.get("claimed_today"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !claimed {
        return Ok(proto::CheckinReport {
            outcome: proto::CheckinOutcome::Failed,
            credit: None,
            streak: None,
            message: Some("领取接口返回成功，但复查仍显示未签到".to_string()),
        });
    }
    Ok(proto::CheckinReport {
        outcome: proto::CheckinOutcome::Claimed,
        credit: Some(format!("{claimable} 积分")),
        streak: after
            .get("daily_task")
            .and_then(|task| task.get("total_claim_days"))
            .and_then(Value::as_u64)
            .map(|value| value as u32),
        message: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_yields_the_numeric_user_id() {
        assert_eq!(user_id_of_scope("v1_public_2119666955975630848"), "2119666955975630848");
        assert_eq!(user_id_of_scope("v2_public_42"), "42");
        assert_eq!(user_id_of_scope("v1_public_abc"), "", "非数字尾段不认");
        assert_eq!(user_id_of_scope(""), "");
    }

    #[test]
    fn query_values_are_escaped() {
        assert_eq!(encode_query("a&b=c+d#e f"), "a%26b%3Dc%2Bd%23e%20f");
        assert_eq!(encode_query("daily_login"), "daily_login");
    }

    #[test]
    fn earliest_expiry_is_picked() {
        let points = json!({
            "groups": [
                { "active": [ { "effectiveEnd": "2026-12-01" }, { "effectiveEnd": "2026-11-20" } ] },
                { "active": [ { "effectiveEnd": "2027-01-01" } ] },
            ]
        });
        assert_eq!(soonest_expiry(&points).as_deref(), Some("2026-11-20"));
        assert_eq!(soonest_expiry(&json!({ "groups": [] })), None);
        assert_eq!(soonest_expiry(&json!({})), None);
    }

    /// 空库（没有 cookies 表）是正常空状态，不是错误。
    #[test]
    fn an_empty_cookie_db_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("teleagent-ck-test-{}", crate::ids::uuid_v4()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        let db = dir.join("Cookies");
        rusqlite::Connection::open(&db).expect("建库").close().expect("关库");
        let cookies = read_cookie_copy(&db).expect("空库应当读成空表");
        assert!(cookies.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
