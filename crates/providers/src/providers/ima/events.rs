//! ima 的 SSE 事件解析（**纯函数**，是这个 provider 里唯一能被完整单测覆盖的部分）。
//!
//! ── 上游事件序列（2026-10-31 参考实现实测）────────────────────
//! ```text
//! TASKS → QA_START(title/icon/trace_id) → SESSION_START(MsgSeqID)
//!       → STRUCTURED_BLOCK(blockMessage.text_message.Text) × N
//!       → SUGGEST_QUESTION → COMPLETED(Code:0) → CLOSE
//! ```
//!
//! ── 正文有**两条**通路，两条都得取 ──────────────────────────────
//! 1. `MESSAGE` 事件的 `Text`（普通模式走这条）；
//! 2. `STRUCTURED_BLOCK` 事件里 `Type == "blockMessage"` 时
//!    `Data.text_message.Text`（copilot 模式走这条）。
//!
//! 只认其中一条会表现成「copilot 账号一个字都不出」或「普通账号一个字都不出」
//! —— 而且 HTTP 是 200、事件流也正常结束，没有任何报错。所以两条都收。
//!
//! ── `COMPLETED.Code` 是**业务**错误码，不是 HTTP 状态 ─────────────
//! 最要紧的一个是 `102005`（模型 API 请求失败）：它的典型成因是 copilot 通道
//! **没传 `model_info`**。上游在这种情况下仍回 HTTP 200、事件流照常跑完，
//! 只在最后一帧给这个 code —— 不检查就等于「用户看到一个空回复，日志里一切正常」。
//!
//! ── 票据轮换 ──────────────────────────────────────────────
//! `COMPLETED` 里可能带新的 `Token` / `RefreshToken`，需要写回账号记录，
//! 否则过一段时间就变「登录过期」。

use serde_json::Value;

/// 一条事件被归并后的**动作**。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// 一段正文增量（两个通路归一后的结果）
    Text(String),
    /// 流正常收尾。`code` 是上游业务码（0 = 成功）
    Completed {
        code: i64,
        message: String,
        /// 上游下发的新票据；没有就是 None
        rotated: Option<(String, String)>,
    },
    /// 上游明确结束（`CLOSE`）
    Closed,
    /// 与正文无关的事件（TASKS / QA_START / SESSION_START / SUGGEST_QUESTION…）
    Ignored,
}

/// 把一帧 `(event, data)` 归并成动作。
///
/// `data` 是 `data:` 行去掉前缀后的原文；不是合法 JSON 时按「无正文」处理
/// —— 上游偶尔会在流里插入心跳或纯文本提示。
pub fn parse(event: &str, data: &str) -> Event {
    let kind = event.trim();
    let payload: Value = match serde_json::from_str(data.trim()) {
        Ok(value) => value,
        Err(_) => {
            // CLOSE 常常没有 body
            return match kind {
                "CLOSE" => Event::Closed,
                _ => Event::Ignored,
            };
        }
    };
    match kind {
        "MESSAGE" => {
            // 普通模式的正文通路
            match text_field(&payload, "Text") {
                Some(text) if !text.is_empty() => Event::Text(text),
                _ => Event::Ignored,
            }
        }
        "STRUCTURED_BLOCK" => {
            // copilot 模式的正文通路。其它 Type（进度、引用、建议…）一律忽略。
            let block_type = text_field(&payload, "Type").unwrap_or_default();
            if block_type != "blockMessage" {
                return Event::Ignored;
            }
            match payload
                .get("Data")
                .and_then(|data| data.get("text_message"))
                .and_then(|message| text_field(message, "Text"))
            {
                Some(text) if !text.is_empty() => Event::Text(text),
                _ => Event::Ignored,
            }
        }
        "COMPLETED" => {
            let code = payload.get("Code").and_then(Value::as_i64).unwrap_or(0);
            let message = text_field(&payload, "Msg")
                .or_else(|| text_field(&payload, "Message"))
                .unwrap_or_default();
            let rotated = match (text_field(&payload, "Token"), text_field(&payload, "RefreshToken")) {
                (Some(token), Some(refresh)) if !token.is_empty() && !refresh.is_empty() => {
                    Some((token, refresh))
                }
                _ => None,
            };
            Event::Completed { code, message, rotated }
        }
        "CLOSE" => Event::Closed,
        _ => Event::Ignored,
    }
}

/// 取字符串字段；数字也接受（有的字段上游下发数字）。
fn text_field(value: &Value, key: &str) -> Option<String> {
    match value.get(key) {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        _ => None,
    }
}

/// 业务错误码 → 给人看的一句话。返回 `None` 表示成功。
///
/// `102005` 单独拆出来讲原因：它是 copilot 通道缺 `model_info` 的典型症状，
/// 而这条信息上游不会告诉你。
pub fn describe_code(code: i64, upstream_message: &str) -> Option<String> {
    match code {
        0 => None,
        102005 => Some(format!(
            "上游模型调用失败（102005）：多半是 copilot 通道没有携带 model_info。\
             上游信息：{upstream_message}"
        )),
        600001 | 401 => Some(format!(
            "ima 登录态已过期（{code}）：请到 ima.qq.com 重新登录并复制完整 Cookie。\
             上游信息：{upstream_message}"
        )),
        other => Some(format!("上游返回错误码 {other}：{upstream_message}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 普通模式的正文通路：`MESSAGE.Text`。
    #[test]
    fn a_message_event_carries_text() {
        let event = parse("MESSAGE", r#"{"Text":"你好"}"#);
        assert_eq!(event, Event::Text("你好".to_string()));
    }

    /// copilot 模式的正文通路：`STRUCTURED_BLOCK` + `blockMessage.text_message.Text`。
    #[test]
    fn a_structured_block_carries_text() {
        let data = r#"{"Type":"blockMessage","Data":{"text_message":{"Text":"来自 copilot"}}}"#;
        assert_eq!(parse("STRUCTURED_BLOCK", data), Event::Text("来自 copilot".to_string()));
    }

    /// 其它 `STRUCTURED_BLOCK` 类型（进度、引用…）不能当成正文吐出来 ——
    /// 那会把「正在搜索…」这类提示混进模型回复里。
    #[test]
    fn a_non_message_structured_block_is_ignored() {
        let data = r#"{"Type":"blockProgress","Data":{"step":"搜索中"}}"#;
        assert_eq!(parse("STRUCTURED_BLOCK", data), Event::Ignored);
    }

    /// 空正文不该产生空 chunk。
    #[test]
    fn an_empty_text_is_ignored() {
        assert_eq!(parse("MESSAGE", r#"{"Text":""}"#), Event::Ignored);
        let data = r#"{"Type":"blockMessage","Data":{"text_message":{"Text":""}}}"#;
        assert_eq!(parse("STRUCTURED_BLOCK", data), Event::Ignored);
    }

    /// 成功的 `COMPLETED`：code 0，没有轮换票据。
    #[test]
    fn a_successful_completion_has_code_zero() {
        let event = parse("COMPLETED", r#"{"Code":0}"#);
        assert_eq!(
            event,
            Event::Completed { code: 0, message: String::new(), rotated: None }
        );
    }

    /// `COMPLETED` 带新票据时要能取出来（不写回就会过一段时间变「登录过期」）。
    #[test]
    fn a_completion_can_carry_rotated_tokens() {
        let event = parse("COMPLETED", r#"{"Code":0,"Token":"new-tk","RefreshToken":"new-rt"}"#);
        assert_eq!(
            event,
            Event::Completed {
                code: 0,
                message: String::new(),
                rotated: Some(("new-tk".to_string(), "new-rt".to_string())),
            }
        );
    }

    /// 只给一半票据不算轮换（写回半份会让下一次请求用错组合）。
    #[test]
    fn a_half_rotated_token_pair_is_not_accepted() {
        let event = parse("COMPLETED", r#"{"Code":0,"Token":"new-tk"}"#);
        assert_eq!(
            event,
            Event::Completed { code: 0, message: String::new(), rotated: None }
        );
    }

    /// `CLOSE` 常常没有 body，也要能认出来。
    #[test]
    fn a_bare_close_is_recognised() {
        assert_eq!(parse("CLOSE", ""), Event::Closed);
        assert_eq!(parse("CLOSE", "  "), Event::Closed);
    }

    /// 与正文无关的事件（含非法 JSON）一律忽略，不能中断整条流。
    #[test]
    fn unrelated_events_are_ignored_without_failing() {
        assert_eq!(parse("TASKS", r#"{"x":1}"#), Event::Ignored);
        assert_eq!(parse("QA_START", r#"{"trace_id":"t"}"#), Event::Ignored);
        assert_eq!(parse("SESSION_START", r#"{"MsgSeqID":"s"}"#), Event::Ignored);
        assert_eq!(parse("SUGGEST_QUESTION", "not json"), Event::Ignored);
    }

    /// 102005 的文案必须点出「缺 model_info」这个真实原因。
    #[test]
    fn the_model_failure_code_explains_itself() {
        let text = describe_code(102005, "模型 API 请求失败").expect("应当有文案");
        assert!(text.contains("102005"), "实际：{text}");
        assert!(text.contains("model_info"), "应当点出真实原因，实际：{text}");
    }

    /// 登录过期码要指路「去网页重新复制 Cookie」（本家没有自动续期）。
    #[test]
    fn the_expired_code_points_at_the_web_login() {
        for code in [600_001, 401] {
            let text = describe_code(code, "登录过期").expect("应当有文案");
            assert!(text.contains("过期"), "实际：{text}");
            assert!(text.contains("Cookie"), "应当指路，实际：{text}");
        }
    }

    /// 0 表示成功，不给文案。
    #[test]
    fn zero_means_success_with_no_message() {
        assert_eq!(describe_code(0, ""), None);
    }

    /// 数字型 `Text` 也要接受（上游字段类型不总是字符串）。
    #[test]
    fn a_numeric_text_field_is_accepted() {
        assert_eq!(parse("MESSAGE", r#"{"Text":42}"#), Event::Text("42".to_string()));
    }
}
