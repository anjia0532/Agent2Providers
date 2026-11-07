//! 七牛云错误分类。
//!
//! ── 顺序即优先级（与参考实现逐条对齐）────────────────────────
//! ```text
//!   1. 上下文超限  → Fatal（原文抛出，让宿主走溢出压缩；
//!                    归 quota 会把账号封到次日零点）
//!   2. 401 / 403   → TokenExpired（账号态，不是模型冷却）
//!   3. 429 / 限流文案 → QuotaLimited(429)
//!   4. 402 / 额度文案 → QuotaLimited（402 按限流呈现）
//!   5. 传输层失败   → Fatal(502)
//!   6. 400 / 422   → Fatal(400)（形状问题，重试无益）
//!   7. >= 500      → Fatal(原状态码)
//! ```
//!
//! ⚠️ 第 2 条「认证先于额度」是一条**事故不变式**：状态码与额度文案并存时
//! （网关侧故障常在报文里捎带 `insufficient quota` 类提示）以状态码为准。
//! 落 quota 会被写成「UTC+8 次日零点」冷却，把一次认证故障放大成封池。
//! 原「额度先判」的方向是反的 —— 宁可漏判额度（不换号）也不误判成封号。

use serde_json::Value;

use agent2api_provider_protocol as proto;

/// 上下文窗口超限的文案特征（全部小写后逐条 `contains`）。
const CONTEXT_WINDOW_PATTERNS: &[&str] = &[
    "maximum context length",
    "context length",
    "context window",
    "context_length_exceeded",
    "reduce the length",
    "too many tokens",
    "input tokens exceed",
];

/// 限流文案特征。
const RATE_LIMIT_PATTERNS: &[&str] = &["too many requests", "rate limit", "throttl"];

/// 额度文案特征。
const QUOTA_PATTERNS: &[&str] = &["insufficient", "quota", "exceed", "balance"];

/// 传输层失败的文案特征（HTTP 状态码此时为 0）。
const TRANSPORT_PATTERNS: &[&str] = &[
    "fetch failed",
    "terminated",
    "econnreset",
    "socket hang up",
    "getaddrinfo",
    "econnrefused",
];

/// 从错误体里抽一段人可读文案（**禁止把整坨 JSON 抛给用户**）。
fn readable_detail(body: &Value) -> String {
    let nested = body
        .get("error")
        .and_then(|error| error.as_object())
        .and_then(|object| object.get("message"))
        .and_then(Value::as_str);
    let parts: Vec<&str> = [
        body.get("message").and_then(Value::as_str),
        nested,
        body.get("msg").and_then(Value::as_str),
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

/// 分类一次失败。`status = 0` 表示传输层失败（请求根本没发出去）。
pub fn classify(status: u16, body: &Value) -> proto::ErrorClass {
    let detail = readable_detail(body);
    let lowered = detail.to_lowercase();
    let code = body
        .get("error")
        .and_then(|error| error.as_object())
        .and_then(|object| object.get("code"))
        .and_then(Value::as_i64)
        .or_else(|| body.get("code").and_then(Value::as_i64));

    // ① 上下文超限：**排在限流/额度/认证之前**
    if status >= 400
        && CONTEXT_WINDOW_PATTERNS
            .iter()
            .any(|pattern| lowered.contains(pattern))
    {
        return proto::ErrorClass::Fatal {
            status: 400,
            message: detail,
            upstream_code: code,
        };
    }

    // ② 认证（先于额度/限流）
    if status == 401 || status == 403 {
        return proto::ErrorClass::TokenExpired { message: detail };
    }

    // ③ 限流
    if status == 429 || RATE_LIMIT_PATTERNS.iter().any(|p| lowered.contains(p)) {
        return proto::ErrorClass::QuotaLimited {
            reset_at: None,
            message: detail,
            upstream_code: code,
            status: 429,
        };
    }

    // ④ 额度
    if status == 402 || QUOTA_PATTERNS.iter().any(|p| lowered.contains(p)) {
        return proto::ErrorClass::QuotaLimited {
            reset_at: None,
            message: detail,
            upstream_code: code,
            // 规格的有意映射：付费失败按限流呈现
            status: 429,
        };
    }

    // ⑤ 传输层
    if status == 0 || TRANSPORT_PATTERNS.iter().any(|p| lowered.contains(p)) {
        return proto::ErrorClass::Fatal {
            status: 502,
            message: detail,
            upstream_code: code,
        };
    }

    // ⑥ 请求形状
    if status == 400 || status == 422 {
        return proto::ErrorClass::Fatal {
            status,
            message: detail,
            upstream_code: code,
        };
    }

    // ⑦ 服务端
    proto::ErrorClass::Fatal {
        status: if status >= 500 { status } else { 502 },
        message: detail,
        upstream_code: code,
    }
}
