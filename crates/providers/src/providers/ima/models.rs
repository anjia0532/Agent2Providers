//! ima 的模型清单：**上游可查**（`POST /cgi-bin/model_manage/get_models`），
//! 但本插件只用它做「这张卡有没有这个模型」的展示，出站请求靠 [`pick_model`]。
//!
//! ── 两个 scene，两套池子 ────────────────────────────────────
//! | scene | 池子 | 特点 |
//! |---|---|---|
//! | `0` | 普通问答 | 纯对话模型（Hy3 / DeepSeek-V4.1-Flash / Hy4 preview / GLM-5.3-Flash） |
//! | `1` | Copilot | 含沙盒 agent 模型 + 付费通道（`official_paid_*`） |
//!
//! ── 为什么默认走 scene 0 + `robot_type=10000` ──────────────────
//! 参考实现实测过两条通道，结论写在它的 `config.py` 里：
//!
//! * **copilot（`robot_type=15`）**：默认池含沙盒 agent 模型，工具调用由沙盒
//!   自执行、**不透传**；显式指定模型还会被 `102005` 锁死。
//! * **普通（`robot_type=10000`）**：纯对话模型池，可以按 `model_info` 指定模型。
//!
//! 所以本插件默认走普通通道。这是「能正常对话」与「看起来接通但工具全废」的区别。
//!
//! ── ⚠️ 显式指定模型有代价 ───────────────────────────────────
//! 有平台真工具的模型（GLM-5.3-Flash / DeepSeek-V4.1-Flash）**会拒绝**注入的
//! tool-call 协议。参考实现的选择是默认用 `Hy4 preview`（纯对话、无平台工具），
//! 用户显式指定时按用户说的走。这里照抄同样的取舍，并在文案里说明。

use serde_json::{json, Value};

/// 上游基址
pub const BASE_URL: &str = "https://ima.qq.com";
/// 建会话
pub const INIT_SESSION_PATH: &str = "/cgi-bin/session_logic/init_session";
/// 提问（SSE）
pub const QA_PATH: &str = "/cgi-bin/assistant/qa";
/// 模型列表
pub const MODELS_PATH: &str = "/cgi-bin/model_manage/get_models";

/// 普通模式（纯对话模型池，可指定模型）
pub const ROBOT_MAIN: i64 = 10_000;

/// 默认 `model_info`：Hy4 preview。
///
/// 选它是因为它**纯对话、无平台工具** ⇒ 注入的 tool-call 协议能被完整遵循。
/// 换成一个带平台工具的模型（GLM-5.3-Flash 之类）会让工具调用在
/// 「平台自己执行」和「透传给客户端」之间打架。
pub const DEFAULT_MODEL_ID: &str = "official_1001";

/// scene=0 的静态兜底清单：`(model_id, model_type, 展示名)`。
///
/// 与 `DEFAULT_MODEL_INFO` 同源（参考实现 `config.py` 的注释里列的四个）。
/// 上游目录拉不到时界面仍要有可选项 —— 只给「自动」一项会让用户以为不能选模型。
const FALLBACK: &[(&str, i64, &str)] = &[
    ("official_1001", 1001, "Hy4 preview"),
    ("official_5", 5, "GLM-5.3-Flash"),
    ("official_4", 4, "DeepSeek-V4.1-Flash"),
    ("official_0", 0, "Hy3"),
];

/// 静态兜底的模型对象列表。
pub fn fallback_models() -> Vec<Value> {
    FALLBACK
        .iter()
        .map(|(id, _, name)| {
            json!({
                "id": name,
                "name": name,
                // 上游没声明上下文与输出上限，**不编造** —— 猜一个会让客户端
                // 的长度预算算错
                "upstreamId": id,
                "supportsToolCall": true,
            })
        })
        .collect()
}

/// 客户端填的模型名 → `model_info` 对象。
///
/// 认不出时**回落到默认模型**而不是报错：ima 的模型名是中文展示名（
/// `Hy4 preview`），客户端填 `ima`、`auto`、空串都是常态。这里把它们统一
/// 当「用默认」处理，与上游「不传 `model_info` 就自己挑」的语义一致，
/// 但**仍然显式传默认那一个** —— copilot 通道不传会直接 `102005`。
pub fn pick_model(requested: &str) -> Value {
    let key = requested.trim().to_ascii_lowercase();
    let matched = FALLBACK.iter().find(|(id, _, name)| {
        let name = name.to_ascii_lowercase();
        // 三种写法都认：展示名、upstreamId、model_type 数字
        name == key || id.to_ascii_lowercase() == key
    });
    match matched {
        Some((id, kind, name)) => json!({ "model_id": id, "model_type": kind, "model_name": name }),
        None => json!({
            "model_id": DEFAULT_MODEL_ID,
            "model_type": 1001,
            "model_name": _default_name(),
        }),
    }
}

fn _default_name() -> &'static str {
    FALLBACK
        .iter()
        .find(|(id, _, _)| *id == DEFAULT_MODEL_ID)
        .map(|(_, _, name)| *name)
        .unwrap_or("Hy4 preview")
}

/// 解析 `get_models` 的响应：`{code:0, models:[{model_id, model_type, model_name, …}]}`。
///
/// 只取三项能用来发请求的字段；其余（描述、积分倍率、灰度标记）与转发无关。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let Some(rows) = payload.get("models").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let Some(id) = row.get("model_id").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if id.is_empty() || !seen.insert(id.to_string()) {
            continue;
        }
        let name = row
            .get("model_name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .unwrap_or(id);
        let kind = row.get("model_type").and_then(Value::as_i64).unwrap_or(0);
        out.push(json!({
            "id": name,
            "name": name,
            "upstreamId": id,
            "modelType": kind,
            "supportsToolCall": true,
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认模型必须是 Hy4 preview：纯对话、无平台工具，工具调用才透传得过去。
    #[test]
    fn the_default_model_is_the_plain_chat_one() {
        let info = pick_model("");
        assert_eq!(info["model_id"], json!(DEFAULT_MODEL_ID));
        assert_eq!(info["model_name"], json!("Hy4 preview"));
    }

    /// 三种写法（展示名 / upstreamId / 大小写不敏感）都要认。
    #[test]
    fn a_model_can_be_named_three_ways() {
        for requested in ["GLM-5.3-Flash", "glm-5.3-flash", "official_5"] {
            let info = pick_model(requested);
            assert_eq!(info["model_id"], json!("official_5"), "输入 {requested}");
            assert_eq!(info["model_type"], json!(5));
        }
    }

    /// `ima` / `auto` / 空串这类占位名回落默认，不报错 —— 客户端习惯这么填。
    #[test]
    fn placeholder_names_fall_back_to_the_default() {
        for requested in ["ima", "auto", "default", "", "  "] {
            assert_eq!(
                pick_model(requested)["model_id"],
                json!(DEFAULT_MODEL_ID),
                "输入 {requested}"
            );
        }
    }

    /// 认不出的模型名也回落默认（不是报错）：上游的模型名随时会变。
    #[test]
    fn an_unknown_name_falls_back_instead_of_failing() {
        assert_eq!(pick_model("gpt-5-nano")["model_id"], json!(DEFAULT_MODEL_ID));
    }

    /// 真实响应形状要能解析。
    #[test]
    fn the_live_model_list_shape_parses() {
        let payload = json!({
            "code": 0,
            "models": [
                {"model_id":"official_1001","model_type":1001,"model_name":"Hy4 preview","describe":"…"},
                {"model_id":"official_5","model_type":5,"model_name":"GLM-5.3-Flash"}
            ]
        });
        let models = parse_models(&payload);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0]["id"], json!("Hy4 preview"));
        assert_eq!(models[0]["upstreamId"], json!("official_1001"));
        assert_eq!(models[1]["modelType"], json!(5));
    }

    /// 重复 id 去重、缺 id 跳过、形状不对给空表（调用方据此保留现有清单）。
    #[test]
    fn malformed_or_duplicate_rows_are_dropped() {
        assert!(parse_models(&json!({})).is_empty());
        let payload = json!({ "models": [
            {"model_id":"a","model_name":"A"},
            {"model_id":"a","model_name":"A"},
            {"model_name":"无 id"},
            {"model_id":"  "}
        ]});
        assert_eq!(parse_models(&payload).len(), 1);
    }

    /// 静态兜底里必须有默认模型，否则「目录拉不到」时下拉框里选不到它。
    #[test]
    fn the_fallback_contains_the_default_model() {
        let ids: Vec<String> = fallback_models()
            .iter()
            .filter_map(|model| model.get("upstreamId").and_then(Value::as_str).map(str::to_string))
            .collect();
        assert!(ids.contains(&DEFAULT_MODEL_ID.to_string()), "实际：{ids:?}");
    }

    /// 兜底清单不能编造上下文窗口与输出上限（上游没给）。
    #[test]
    fn the_fallback_does_not_invent_token_limits() {
        for model in fallback_models() {
            assert!(model.get("context").is_none(), "不该编造 context：{model}");
            assert!(model.get("maxTokens").is_none(), "不该编造 maxTokens：{model}");
        }
    }
}
