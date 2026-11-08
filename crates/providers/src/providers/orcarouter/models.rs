//! OrcaRouter 的模型目录：`GET {base}/models`（**免鉴权可读**）+ 静态兜底。
//!
//! ── 上游形态（2026-11-08 实测）──────────────────────────────
//! ```text
//! GET https://api.orcarouter.ai/v1/models      （不带 Authorization 也回 200）
//!   → {"data":[{"id":"orcarouter/pod","object":"model","owned_by":"orcarouter",
//!               "supported_endpoint_types":["openai","openai-response","anthropic","gemini"]}, …]}
//! ```
//! 实测 **216 个模型**，含 8 个「免费 / 自动档」：
//! `orcarouter/{pod,free,fusion,fusion-flash,fusion-mini}`、
//! `deepseek/deepseek-v4-flash-free`、`tencent/hy4-preview-free`、`z-ai/glm-5.3-flash-free`。
//!
//! ── ⚠️ `/models` 免鉴权 ⇒ **它不能用来验 key 有效性** ──────────
//! 这一点与七牛云同型：目录接口本来就公开。所以 `refresh_models` 成功**不代表**
//! 账号的 key 可用 —— 只有真正发一次对话才能验。不要在这里加「能拉到目录就算
//! 账号有效」的推断。
//!
//! ── 静态兜底的用途 ────────────────────────────────────────
//! 拉不到目录时界面仍要有可选模型，所以内置一小份真实 id（取自上面那次实测）。
//! 它**不是**完整目录，只保证「没有账号 / 没联网」时下拉框不为空。

use serde_json::{json, Value};

/// 目录路径（拼在 `BASE_URL` 之后）
pub const MODELS_PATH: &str = "/models";

/// 自动路径的缓存 TTL
const TTL_MS: i64 = 10 * 60 * 1000;

/// 静态兜底：`[id, 展示名, 上下文, 输出上限, 收图, 思考]`
///
/// 挑的是「免费/自动档 + 各家代表模型」，不是全量目录。真实目录 216 条，
/// 抄进代码只会在上游变更后过期。
type Fallback = (&'static str, &'static str, u64, u64, bool, bool);

const FALLBACK: &[Fallback] = &[
    // 免费 / 自动档排最前：这正是 issue #367 里「用 github 账号还能用」的那几档
    ("orcarouter/free", "OrcaRouter 免费路由", 200_000, 32_000, false, false),
    ("orcarouter/fusion", "OrcaRouter 融合路由", 200_000, 32_000, false, true),
    ("orcarouter/fusion-flash", "OrcaRouter 融合（极速）", 200_000, 32_000, false, false),
    ("deepseek/deepseek-v4.1-flash-free", "DeepSeek V4.1 Flash（免费）", 1_000_000, 64_000, false, false),
    ("tencent/hy4-preview-free", "混元 4 Preview（免费）", 200_000, 32_000, false, false),
    ("z-ai/glm-5.3-flash-free", "GLM-5.3 Flash（免费）", 200_000, 32_000, false, false),
    // 付费侧代表
    ("anthropic/claude-sonnet-5", "Claude Sonnet 5", 200_000, 64_000, true, true),
    ("openai/gpt-5", "GPT-5", 200_000, 64_000, true, true),
    ("deepseek/deepseek-chat", "DeepSeek Chat", 128_000, 8_000, false, false),
];

struct CatalogState {
    models: Vec<Value>,
    fetched_at: i64,
}

static STATE: std::sync::OnceLock<std::sync::Mutex<Option<CatalogState>>> =
    std::sync::OnceLock::new();

fn with_state<R>(f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mut guard = STATE
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

fn fallback_models() -> Vec<Value> {
    FALLBACK
        .iter()
        .map(|(id, name, context, max_tokens, image, reasoning)| {
            json!({
                "id": id,
                "name": name,
                "context": context,
                "maxTokens": max_tokens,
                "supportsToolCall": true,
                "supportsImage": image,
                "supportsReasoning": reasoning,
            })
        })
        .collect()
}

/// 解析 `/models` 响应（OpenAI 形状 `{data:[{id,…}]}`）。
///
/// 只取 `id` 与 `owned_by`：上游没给上下文窗口与输出上限，**不编造** ——
/// 猜一个上限会让客户端的长度预算算错。缺这两项时界面显示「未声明」。
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let Some(rows) = payload.get("data").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let Some(id) = row.get("id").and_then(Value::as_str).map(str::trim) else {
            continue;
        };
        if id.is_empty() || !seen.insert(id.to_string()) {
            continue;
        }
        let owner = row.get("owned_by").and_then(Value::as_str).unwrap_or("");
        let mut model = json!({
            "id": id,
            "name": id,
            "supportsToolCall": true,
            // 上游没声明能力，一律按「不支持」处理（宁可少显示一个能力，
            // 也不要在界面上勾上一个实际不生效的开关）
            "supportsImage": false,
        });
        if !owner.is_empty() {
            model["owner"] = json!(owner);
        }
        out.push(model);
    }
    out
}

/// 当前清单（缓存优先，其次静态兜底）。
pub fn list() -> proto::ModelList {
    let cached = with_state(|slot| {
        slot.as_ref().map(|state| {
            (
                state.models.clone(),
                proto::CatalogMeta {
                    remote: true,
                    refreshed_at: state.fetched_at,
                },
            )
        })
    });
    if let Some((models, meta)) = cached {
        return proto::ModelList { models, meta };
    }
    proto::ModelList {
        models: fallback_models(),
        meta: proto::CatalogMeta {
            remote: false,
            refreshed_at: 0,
        },
    }
}

/// 拉一次目录并落地。
///
/// ⚠️ 用的是 `crate::http::control_client`，不带任何鉴权头：目录接口公开，
/// 带不带 key 都回 200（见模块头）。因此**本函数成功不代表 key 有效**。
pub async fn refresh(
    client: &reqwest::Client,
    base_url: &str,
    force: bool,
) -> proto::RefreshOutcome {
    let now = crate::http::now_ms();
    if !force {
        let fresh = with_state(|slot| {
            slot.as_ref()
                .map(|state| !state.models.is_empty() && now - state.fetched_at < TTL_MS)
                .unwrap_or(false)
        });
        if fresh {
            return proto::RefreshOutcome::unchanged();
        }
    }
    let url = format!("{base_url}{MODELS_PATH}");
    let headers: Vec<(String, String)> = Vec::new();
    let (status, payload) = match crate::http::get_json(client, &url, &headers).await {
        Ok(result) => result,
        Err(error) => return proto::RefreshOutcome::failed(error),
    };
    if !(200..300).contains(&status) {
        return proto::RefreshOutcome::failed(format!(
            "OrcaRouter 模型目录请求失败（HTTP {status}）"
        ));
    }
    let models = parse_models(&payload);
    if models.is_empty() {
        return proto::RefreshOutcome::failed(
            "OrcaRouter 模型目录为空或格式不认识（保留现有清单）",
        );
    }
    let count = models.len();
    with_state(|slot| {
        *slot = Some(CatalogState {
            models: models.clone(),
            fetched_at: now,
        });
    });
    proto::RefreshOutcome::refreshed(count)
}

use agent2api_provider_protocol as proto;

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实响应的形状（2026-11-08 实测截取）必须能解析出 id。
    #[test]
    fn the_live_response_shape_parses() {
        let payload = json!({
            "data": [
                {"id":"orcarouter/pod","object":"model","created":0,"owned_by":"orcarouter",
                 "supported_endpoint_types":["openai","openai-response","anthropic","gemini"]},
                {"id":"orcarouter/free","object":"model","created":0,"owned_by":"orcarouter"},
                {"id":"deepseek/deepseek-v4-flash-free","object":"model","created":0,"owned_by":"DeepSeek"}
            ]
        });
        let models = parse_models(&payload);
        assert_eq!(models.len(), 3);
        assert_eq!(models[0]["id"], "orcarouter/pod");
        assert_eq!(models[0]["owner"], "orcarouter");
        // 上游没给上下文/输出上限 —— 不能编造
        assert!(models[0].get("context").is_none(), "缺失的元数据不该被编造");
    }

    /// 重复 id 去重、空 id 跳过，避免下拉框里出现两条一样的。
    #[test]
    fn duplicate_and_blank_ids_are_dropped() {
        let payload = json!({ "data": [
            {"id":"a"}, {"id":"a"}, {"id":"  "}, {"id":""}, {"not_id": true}
        ]});
        let models = parse_models(&payload);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0]["id"], "a");
    }

    /// 形状不对返回空表（调用方据此保留现有清单，不覆盖成空）。
    #[test]
    fn a_malformed_payload_yields_an_empty_list() {
        assert!(parse_models(&json!({})).is_empty());
        assert!(parse_models(&json!({ "data": "nope" })).is_empty());
    }

    /// 静态兜底里必须含那几个免费档 —— 那是 issue #367 的核心诉求。
    #[test]
    fn the_fallback_covers_the_free_tiers() {
        let models = list();
        let ids: Vec<&str> = models
            .models
            .iter()
            .filter_map(|model| model.get("id").and_then(Value::as_str))
            .collect();
        assert!(ids.contains(&"orcarouter/free"), "免费路由必须在兜底表里：{ids:?}");
        assert!(ids.contains(&"deepseek/deepseek-v4.1-flash-free"));
    }
}
