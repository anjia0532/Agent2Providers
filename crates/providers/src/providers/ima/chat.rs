//! ima 对话：**建会话 → 提问 SSE → 折成 OpenAI 帧**。
//!
//! ── 上游是两步（`build_chat` 装不下）──────────────────────────
//! ```text
//!   ① POST /cgi-bin/session_logic/init_session
//!        {"session_type":0,"env_info":{"robot_type":10000}}
//!        → {"session_id":"<40 位 hex>", …}
//!   ② POST /cgi-bin/assistant/qa     （SSE）
//!        {"session_id","robot_type":10000,"question",…,"model_info":{…}}
//! ```
//! `ChatPlan` 只能表达一次请求，所以本家走 `conversation()` 的推模型：
//! 自己发两次 HTTP，再往 sink 里推 OpenAI 帧。
//!
//! ── 每轮新建会话（**不是**复用）────────────────────────────────
//! 上游把历史留在服务端，但输入通道只有一条 `question`；而 OpenAI 客户端每轮
//! 自带全量 `messages`。所以这里**每个请求新建一个会话**，历史拍平成输入文本。
//! 无注册表、无指纹链、重启即忘 —— 与 OrcaTerm / KukuAI 同一口径。
//!
//! 参考实现另有一条实测记录：同一 session 连续多次 qa 会被限流（提示「版本过低」）。
//! 每轮新建天然规避这条。
//!
//! ── 401 / 600001 不做自愈 ───────────────────────────────────
//! 本家刷新接口在 ima 原生层，**无法自动续期**（参考实现原话）。所以票据过期时
//! 直接把可操作的文案抛给用户（去网页重新复制 Cookie），而不是「续期一次再试」
//! —— 后者只会多打一次上游然后同样失败。

use agent2api_provider_protocol as proto;
use agent2api_provider_sdk::{ConversationSink, PluginCtx};
use serde_json::{json, Map, Value};

use super::credentials::{self, Credentials};
use super::events::{self, Event};
use super::models::{self, BASE_URL, INIT_SESSION_PATH, MODELS_PATH, QA_PATH, ROBOT_MAIN};

/// 上游的错误码里表示「登录态失效」的那几个。
const TOKEN_EXPIRED_CODES: &[i64] = &[600_001, 401];

/// 一次 SSE 消费的落点：OpenAI 帧。
enum Frame {
    Chunk(Value),
    Error(String),
    Done,
}

impl Frame {
    fn wire(&self) -> String {
        match self {
            Frame::Chunk(chunk) => format!("data: {chunk}\n\n"),
            Frame::Error(message) => format!(
                "data: {}\n\n",
                json!({ "error": { "message": message, "type": "upstream_error" } })
            ),
            Frame::Done => "data: [DONE]\n\n".to_string(),
        }
    }
}

/// 转发入口。
pub async fn run(
    ctx: &PluginCtx,
    req: proto::ConversationRequest,
    mut sink: ConversationSink<'_>,
) -> Result<(), String> {
    let credentials = {
        let found = ctx
            .store_get(super::ID, &req.account)
            .await
            .map_err(|error| format!("读取 ima 账号失败：{error}"))?;
        credentials::from_secret(&found.secret)?
    };
    let client_model = req
        .body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let question = build_question(req.body.get("messages"));

    // 控制面客户端只用于建会话（短请求）；流式那步单独用 stream_client
    let control = crate::http::control_client(req.proxy.as_ref(), &ctx.env.proxy);
    let session_id = init_session(&control, &credentials, req.proxy.as_ref(), &ctx.env.proxy).await?;

    // 提问：流式
    let payload = qa_payload(&session_id, &question, &client_model);
    let stream_client = crate::http::stream_client(req.proxy.as_ref(), &ctx.env.proxy);
    let response = crate::http::post_stream(
        &stream_client,
        &format!("{BASE_URL}{QA_PATH}"),
        &headers(&credentials),
        &payload,
        "text/event-stream",
    )
    .await?;
    if !response.is_success() {
        let body = response.error_body.unwrap_or_default();
        let hint = if body.contains("600001") || body.contains("登录") {
            "（登录态可能已过期，请到 ima.qq.com 重新登录并复制完整 Cookie）"
        } else {
            ""
        };
        return Err(format!("ima 提问失败（HTTP {}）：{body}{hint}", response.status));
    }
    let Some(stream) = response.response else {
        return Err("ima 提问失败：上游没有返回响应体".to_string());
    };

    sink.head(proto::StreamHead {
        status: 200,
        headers: header_map(&[("content-type".to_string(), "text/event-stream".to_string())]),
        upstream: proto::UpstreamKind::Chat,
    })
    .await?;

    // ── 逐帧消费 ──────────────────────────────────────────────
    let mut emitter = Emitter::new(&client_model);
    let mut scanner = SseScanner::default();
    let mut source = crate::response_stream::sse(stream);
    use futures::StreamExt;
    while let Some(item) = source.next().await {
        match item {
            Err(error) => {
                let frames = emitter.fail(&format!("ima 对话流处理中断：{error}"));
                push_frames(&mut sink, frames).await?;
                return Ok(());
            }
            Ok(bytes) => {
                let frames = emitter.feed(&mut scanner, &bytes);
                push_frames(&mut sink, frames).await?;
                if emitter.finished {
                    return Ok(());
                }
            }
        }
    }
    let frames = emitter.finish(&mut scanner);
    push_frames(&mut sink, frames).await?;
    Ok(())
}

/// 建会话，返回 `session_id`。
async fn init_session(
    client: &reqwest::Client,
    credentials: &Credentials,
    proxy: Option<&proto::WireProxy>,
    gateway_proxy: &str,
) -> Result<String, String> {
    let _ = (proxy, gateway_proxy);
    let body = json!({ "session_type": 0, "env_info": { "robot_type": ROBOT_MAIN } });
    let (status, payload) = crate::http::post_json(
        client,
        &format!("{BASE_URL}{INIT_SESSION_PATH}"),
        &headers(credentials),
        &body,
    )
    .await?;
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if status == 401 || TOKEN_EXPIRED_CODES.contains(&code) {
        return Err(format!(
            "ima 登录态已过期（HTTP {status} / code {code}）：请到 ima.qq.com 重新登录并复制完整 Cookie"
        ));
    }
    if let Some(session_id) = payload.get("session_id").and_then(Value::as_str) {
        if !session_id.trim().is_empty() {
            return Ok(session_id.trim().to_string());
        }
    }
    Err(format!("ima 建会话失败（HTTP {status}）：{payload}"))
}

/// 组装提问体。
///
/// `question_type: 3` + `history_info` + `client_tools` 这三项看着像冗余，
/// 但参考实现记录「它们是服务端信任 `model_info` 的必要字段」—— 少传会让
/// 显式指定的模型静默回落到默认。
fn qa_payload(session_id: &str, question: &str, requested_model: &str) -> Value {
    json!({
        "session_id": session_id,
        "robot_type": ROBOT_MAIN,
        "question": question,
        "question_type": 3,
        "client_id": format!("cli-{}", short_hex()),
        "command_info": { "command_type": 0, "params": {} },
        "attach_media": [],
        "history_info": { "type": 0 },
        "client_tools": [],
        "model_info": models::pick_model(requested_model),
    })
}

/// 历史拍平成一条输入文本。
///
/// ── 为什么带上角色前缀 ──────────────────────────────────────
/// 上游只有一个 `question` 通道，没有角色概念。不标角色的话，多轮对话里
/// 「用户问 / 助手答」会被拼成一段连续自述，模型容易接着自己的话往下编。
pub fn build_question(messages: Option<&Value>) -> String {
    let Some(rows) = messages.and_then(Value::as_array) else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    for row in rows {
        let role = row.get("role").and_then(Value::as_str).unwrap_or("user");
        let text = content_text(row.get("content"));
        if text.trim().is_empty() {
            continue;
        }
        let label = match role {
            "assistant" => "助手",
            "system" => "系统",
            "tool" => "工具",
            _ => "用户",
        };
        parts.push(format!("{label}：{text}"));
    }
    parts.join("\n\n")
}

/// `content` 可能是字符串，也可能是分块数组（OpenAI 多模态形态）。
fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| {
                // 只要文本块；图片/文件块在纯文本通道里没有对应表达
                if block.get("type").and_then(Value::as_str) == Some("text") {
                    block.get("text").and_then(Value::as_str).map(str::to_string)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// 请求头。
fn headers(credentials: &Credentials) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Origin".to_string(), "https://ima.qq.com".to_string()),
        ("Referer".to_string(), "https://ima.qq.com/".to_string()),
        ("User-Agent".to_string(), super::USER_AGENT.to_string()),
        ("Cookie".to_string(), credentials.cookie_header()),
        // 可选但带上：不带也能 200，带上是为了上游某天开始校验时不至于变成笼统 401
        ("x-ima-bkn".to_string(), credentials::bkn(&credentials.token).to_string()),
    ]
}

fn header_map(headers: &[(String, String)]) -> std::collections::BTreeMap<String, String> {
    headers.iter().cloned().collect()
}

/// 短随机十六进制（16 位），用于 `client_id`。
fn short_hex() -> String {
    super::random_hex(8)
}

async fn push_frames(sink: &mut ConversationSink<'_>, frames: Vec<Frame>) -> Result<(), String> {
    for frame in frames {
        sink.send(frame.wire().as_bytes()).await?;
    }
    Ok(())
}

/// 增量 SSE 扫描器：把字节流切成 `(event, data)` 对。
///
/// 自己写而不复用别家的，是因为 ima 的帧形态简单（`event:` + `data:` 两行），
/// 而别家的扫描器都绑着各自的业务字段。
#[derive(Default)]
pub struct SseScanner {
    buffer: Vec<u8>,
    event: String,
}

impl SseScanner {
    /// 喂一段字节，返回本段能完整解析出的 `(event, data)` 列表。
    pub fn push(&mut self, bytes: &[u8]) -> Vec<(String, String)> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let Some(index) = find_line_end(&self.buffer) else { break };
            let line: Vec<u8> = self.buffer.drain(..index).collect();
            // 吃掉行尾（\n 或 \r\n）
            while matches!(self.buffer.first(), Some(b'\n') | Some(b'\r')) {
                self.buffer.remove(0);
            }
            let Ok(line) = String::from_utf8(line) else { continue };
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                self.event.clear();
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                self.event = rest.trim().to_string();
                continue;
            }
            if let Some(rest) = line.strip_prefix("data:") {
                let data = rest.trim().to_string();
                if !data.is_empty() {
                    out.push((self.event.clone(), data));
                }
            }
        }
        out
    }
}

fn find_line_end(buffer: &[u8]) -> Option<usize> {
    buffer.iter().position(|byte| *byte == b'\n')
}

/// 把事件流折成 OpenAI 帧。
struct Emitter {
    id: String,
    created: i64,
    model: String,
    /// 已发过内容 —— 用于错误兜底：已经吐了一半正文就不该再改判成错误
    emitted: bool,
    finished: bool,
}

impl Emitter {
    fn new(model: &str) -> Self {
        let now = crate::http::now_ms();
        Self {
            id: format!("chatcmpl-ima-{now}"),
            created: now / 1000,
            model: model.to_string(),
            emitted: false,
            finished: false,
        }
    }

    fn feed(&mut self, scanner: &mut SseScanner, bytes: &[u8]) -> Vec<Frame> {
        if self.finished {
            return Vec::new();
        }
        let events = scanner.push(bytes);
        let mut frames = Vec::new();
        for (event, data) in events {
            match events::parse(&event, &data) {
                Event::Text(text) => {
                    self.emitted = true;
                    frames.push(self.chunk(Some(text), None));
                }
                Event::Completed { code, message, rotated } => {
                    if let Some(text) = events::describe_code(code, &message) {
                        // 上游业务失败：已经吐过正文就照常收尾（否则会把半截
                        // 正文变成错误，客户端拿到的内容是断的）
                        if !self.emitted {
                            frames.push(Frame::Error(text));
                            frames.push(Frame::Done);
                            self.finished = true;
                            return frames;
                        }
                        let _ = rotated;
                    }
                    let _ = rotated;
                    frames.push(self.chunk(None, Some("stop")));
                    frames.push(Frame::Done);
                    self.finished = true;
                    return frames;
                }
                Event::Closed => {
                    if !self.finished {
                        frames.push(self.chunk(None, Some("stop")));
                        frames.push(Frame::Done);
                        self.finished = true;
                    }
                    return frames;
                }
                Event::Ignored => {}
            }
        }
        frames
    }

    fn finish(&mut self, scanner: &mut SseScanner) -> Vec<Frame> {
        if self.finished {
            return Vec::new();
        }
        let mut frames = self.feed(scanner, b"");
        // 上游没给 COMPLETED / CLOSE 就断流：照常收尾，别让客户端一直等
        if !self.finished {
            frames.push(self.chunk(None, Some("stop")));
            frames.push(Frame::Done);
            self.finished = true;
        }
        frames
    }

    fn fail(&mut self, message: &str) -> Vec<Frame> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        if self.emitted {
            // 已经吐过内容：只收尾，不再报错（错误会覆盖掉已收到的正文）
            vec![self.chunk(None, Some("stop")), Frame::Done]
        } else {
            vec![Frame::Error(message.to_string()), Frame::Done]
        }
    }

    fn chunk(&mut self, delta: Option<String>, finish_reason: Option<&str>) -> Frame {
        let mut choice = Map::new();
        choice.insert("index".to_string(), json!(0));
        match delta {
            Some(text) if !text.is_empty() => {
                choice.insert("delta".to_string(), json!({ "content": text }));
            }
            _ => {
                choice.insert("delta".to_string(), json!({}));
            }
        }
        if let Some(reason) = finish_reason {
            choice.insert("finish_reason".to_string(), json!(reason));
        }
        let mut chunk = Map::new();
        chunk.insert("id".to_string(), json!(self.id));
        chunk.insert("object".to_string(), json!("chat.completion.chunk"));
        chunk.insert("created".to_string(), json!(self.created));
        chunk.insert("model".to_string(), json!(self.model));
        chunk.insert("choices".to_string(), json!([Value::Object(choice)]));
        Frame::Chunk(Value::Object(chunk))
    }
}

/// 给 `models` 刷新用：拉一次上游目录。
pub async fn fetch_models(
    client: &reqwest::Client,
    credentials: &Credentials,
    scene: i64,
) -> Result<Vec<Value>, String> {
    let body = json!({ "scene": scene });
    let (status, payload) = crate::http::post_json(
        client,
        &format!("{BASE_URL}{MODELS_PATH}"),
        &headers(credentials),
        &body,
    )
    .await?;
    let code = payload.get("code").and_then(Value::as_i64).unwrap_or(0);
    if status == 401 || TOKEN_EXPIRED_CODES.contains(&code) {
        return Err("ima 登录态已过期，请重新复制 Cookie".to_string());
    }
    Ok(models::parse_models(&payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 历史拍平要保留角色标记 —— 否则多轮对话会被拼成一段连续自述。
    #[test]
    fn the_history_is_flattened_with_role_labels() {
        let messages = json!([
            { "role": "system", "content": "你是助手" },
            { "role": "user", "content": "你好" },
            { "role": "assistant", "content": "在的" },
        ]);
        let question = build_question(Some(&messages));
        assert!(question.contains("系统：你是助手"), "实际：{question}");
        assert!(question.contains("用户：你好"), "实际：{question}");
        assert!(question.contains("助手：在的"), "实际：{question}");
    }

    /// 分块数组形态的 `content` 只取文本块（图片块在纯文本通道没有表达）。
    #[test]
    fn an_array_content_takes_only_text_blocks() {
        let messages = json!([{ "role": "user", "content": [
            { "type": "text", "text": "描述这张图" },
            { "type": "image_url", "image_url": { "url": "data:…" } }
        ]}]);
        let question = build_question(Some(&messages));
        assert!(question.contains("描述这张图"));
        assert!(!question.contains("image_url"), "不该把图片块塞进文本：{question}");
    }

    /// 空 content 的行跳过，不在输入里留「用户：」这种空壳。
    #[test]
    fn an_empty_message_is_skipped() {
        let messages = json!([
            { "role": "user", "content": "   " },
            { "role": "assistant", "content": "" },
            { "role": "user", "content": "有效" },
        ]);
        assert_eq!(build_question(Some(&messages)), "用户：有效");
    }

    /// 没有 messages 时给空串（调用方会把它当一次空提问，由上游决定怎么回）。
    #[test]
    fn a_missing_history_is_an_empty_question() {
        assert_eq!(build_question(None), "");
        assert_eq!(build_question(Some(&json!("nope"))), "");
    }

    /// 提问体必须带上那三个「让服务端信任 model_info」的字段。
    #[test]
    fn the_qa_payload_carries_the_fields_that_make_model_info_trusted() {
        let payload = qa_payload("sid-1", "你好", "Hy4 preview");
        assert_eq!(payload["session_id"], json!("sid-1"));
        assert_eq!(payload["robot_type"], json!(ROBOT_MAIN));
        assert_eq!(payload["question_type"], json!(3));
        assert_eq!(payload["history_info"], json!({ "type": 0 }));
        assert_eq!(payload["client_tools"], json!([]));
        assert_eq!(payload["model_info"]["model_id"], json!("official_1001"));
        assert!(
            payload["client_id"].as_str().is_some_and(|id| id.starts_with("cli-")),
            "client_id 应当是 cli- 前缀"
        );
    }

    /// SSE 扫描器：一条完整的 `event:` + `data:` 帧。
    #[test]
    fn the_scanner_splits_events_and_data() {
        let mut scanner = SseScanner::default();
        let events = scanner.push(b"event: MESSAGE\ndata: {\"Text\":\"hi\"}\n\n");
        assert_eq!(events, vec![("MESSAGE".to_string(), r#"{"Text":"hi"}"#.to_string())]);
    }

    /// 帧被切在三段里也要能拼回来（真实网络下必然发生）。
    #[test]
    fn the_scanner_handles_frames_split_across_chunks() {
        let mut scanner = SseScanner::default();
        assert!(scanner.push(b"event: MES").is_empty());
        assert!(scanner.push(b"SAGE\ndata: {\"Te").is_empty());
        let events = scanner.push(b"xt\":\"hi\"}\n\n");
        assert_eq!(events, vec![("MESSAGE".to_string(), r#"{"Text":"hi"}"#.to_string())]);
    }

    /// `\r\n` 行尾也要认（有的代理会改写行尾）。
    #[test]
    fn the_scanner_accepts_crlf_line_endings() {
        let mut scanner = SseScanner::default();
        let events = scanner.push(b"event: CLOSE\r\ndata: {}\r\n\r\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "CLOSE");
    }

    /// 空 data 行（心跳）不产生事件。
    #[test]
    fn a_heartbeat_data_line_is_skipped() {
        let mut scanner = SseScanner::default();
        assert!(scanner.push(b"event: PING\ndata:\n\n").is_empty());
    }
}
