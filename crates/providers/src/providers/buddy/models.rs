//! CodeBuddy 模型目录：`/v3/config` 动态拉取 + 静态兜底。
//!
//! ── 上游形态（实测）──────────────────────────────────────────
//! ```text
//! GET https://copilot.tencent.com/v3/config
//!   → {data:{agents:[{name:"craft",models:["hy4-preview", …]}, …],
//!             models:[{id,name,maxInputTokens,supportsImages,reasoning:{…}}]}}
//! ```
//!
//! ── 解析策略（顺序即优先级）──────────────────────────────────
//!   1. **craft agent 引用的模型** —— 主对话模型，排在最前（中国版由它列出
//!      `hy4-preview` / `glm-5.3` 等具体 id）；
//!   2. **`data.models` 里剩余的可对话模型** —— 国际版的 craft 只引用抽象别名，
//!      其余可用模型只出现在 `data.models` 里；
//!   3. **试用模型**（`productFeaturesConfig.ModelTrialBanner`）。
//!
//! 过滤：跳过 `auto`（自动选择，非真实模型）、生图等非对话用途、
//! 以及 `nes-` / `completion-` 等专用前缀。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;

use super::BUDDY;
use crate::http;

/// 配置端点
pub const CONFIG_PATH: &str = "/v3/config";

/// 自动路径的缓存 TTL
const TTL_MS: i64 = 10 * 60 * 1000;

/// 承载「输入框可选模型」的 agent 名，按优先级。
const PREFERRED_AGENT_NAMES: &[&str] = &["craft", "cli"];

/// 兜底模型：`[id, 展示名, 上下文窗口, 输出上限, 收图, 档位表]`
type Fallback =
    (&'static str, &'static str, u64, u64, bool, &'static [&'static str]);

/// 静态兜底表（对齐 `/v3/config` 的 craft agent models；动态拉取失败时用）。
///
/// ⚠️ 取 128000 而非 131072：前者是服务端**真正接受**的额度（scoped 端点），
/// 131072 是 `/v3/config` 的声明值；取小者避免因端点差异被上游拒绝。
const FALLBACK: &[Fallback] = &[
    ("hy4-preview", "Hy4 preview", 1_000_000, 64_000, true, &["high"]),
    ("hy3", "Hy3", 192_000, 64_000, true, &["low", "high"]),
    ("hy3-x", "Hy3", 192_000, 64_000, true, &["low", "high"]),
    (
        "deepseek-v4.1-flash",
        "Deepseek-V4.1-Flash",
        1_000_000,
        128_000,
        true,
        &["low", "high", "max"],
    ),
    (
        "deepseek-v4-pro",
        "Deepseek-V4-Pro",
        1_000_000,
        128_000,
        true,
        &["low", "high", "xhigh"],
    ),
    (
        "deepseek-v4-flash",
        "Deepseek-V4-Flash",
        1_000_000,
        50_000,
        true,
        &["low", "high", "max"],
    ),
    ("glm-5.3", "GLM-5.3", 1_000_000, 64_000, true, &["low", "high", "max"]),
    (
        "glm-5.3-flash",
        "GLM-5.3-Flash",
        1_000_000,
        32_000,
        true,
        &["low", "high", "max"],
    ),
    ("glm-5.2", "GLM-5.2", 1_000_000, 64_000, true, &["high", "xhigh"]),
    ("glm-5.1", "GLM-5.1", 200_000, 48_000, true, &["medium"]),
    ("glm-5v-turbo", "GLM-5V-Turbo", 200_000, 64_000, true, &["medium"]),
    ("kimi-k3-1", "Kimi-K3-1", 1_000_000, 32_000, true, &["medium"]),
    (
        "kimi-k2.8-preview",
        "Kimi-K2.8-Preview",
        1_000_000,
        64_000,
        true,
        &["low", "high", "max"],
    ),
    ("kimi-k2.7", "Kimi-K2.7", 256_000, 32_000, true, &["medium"]),
    ("kimi-k2.6", "Kimi-K2.6", 256_000, 32_000, true, &["medium"]),
    ("minimax-m3", "MiniMax-M3", 512_000, 64_000, true, &["medium"]),
];

struct CatalogState {
    models: Vec<Value>,
    fetched_at: i64,
}

static STATE: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();

fn state() -> &'static Mutex<Option<CatalogState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

fn with_state<R>(f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mut guard = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 静态兜底清单（动态拉取失败时用）
pub fn fallback_models() -> Vec<Value> {
    FALLBACK
        .iter()
        .map(|(id, name, context, max_tokens, image, efforts)| {
            let mut model = json!({
                "id": id,
                "name": name,
                "supportsToolCall": true,
                "supportsImage": image,
                "context": context,
                "maxTokens": max_tokens,
            });
            if !efforts.is_empty() {
                model["reasoning"] = json!({ "efforts": efforts });
            }
            model
        })
        .collect()
}

/// `auto` 等自动选择别名（不是真实模型）
fn is_auto_alias(id: &str) -> bool {
    matches!(id, "auto" | "default-model" | "fast-model" | "long-model" | "smart-model")
        || id.ends_with("-free")
}

/// 非对话用途 / 专用前缀
fn is_non_chat(id: &str) -> bool {
    id.starts_with("nes-") || id.starts_with("completion-") || id.starts_with("text-to-image")
}

/// 归一一条远端模型。
fn normalize(id: &str, meta: Option<&Value>) -> Option<Value> {
    if is_auto_alias(id) || is_non_chat(id) {
        return None;
    }
    let name = meta
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(id);
    let context = meta
        .and_then(|value| value.get("maxInputTokens"))
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .unwrap_or(0);
    let supports_image = meta
        .and_then(|value| value.get("supportsImages"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut model = json!({
        "id": id,
        "name": name,
        "supportsToolCall": true,
        "supportsImage": supports_image,
    });
    if context > 0 {
        model["context"] = json!(context);
    }
    if let Some(efforts) = meta
        .and_then(|value| value.get("reasoning"))
        .and_then(|value| value.get("efforts"))
        .and_then(Value::as_array)
    {
        let list: Vec<String> = efforts
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect();
        if !list.is_empty() {
            model["reasoning"] = json!({ "efforts": list });
        }
    }
    Some(model)
}

/// 解析 `/v3/config`。
pub fn parse_config(payload: &Value) -> Vec<Value> {
    let Some(data) = payload.get("data").and_then(Value::as_object) else {
        return Vec::new();
    };
    let empty = Vec::new();
    let remote_models = data.get("models").and_then(Value::as_array).unwrap_or(&empty);
    let meta_by_id: std::collections::HashMap<&str, &Value> = remote_models
        .iter()
        .filter_map(|model| {
            model
                .get("id")
                .and_then(Value::as_str)
                .map(|id| (id, model))
        })
        .collect();

    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let push = |id: &str, out: &mut Vec<Value>, seen: &mut std::collections::HashSet<String>| {
        if !seen.insert(id.to_string()) {
            return;
        }
        if let Some(model) = normalize(id, meta_by_id.get(id).copied()) {
            out.push(model);
        }
    };

    // 1. craft（或 cli）agent 引用的模型优先
    if let Some(agents) = data.get("agents").and_then(Value::as_array) {
        for agent_name in PREFERRED_AGENT_NAMES {
            let Some(agent) = agents
                .iter()
                .find(|agent| agent.get("name").and_then(Value::as_str) == Some(agent_name))
            else {
                continue;
            };
            if let Some(models) = agent.get("models").and_then(Value::as_array) {
                for id in models.iter().filter_map(Value::as_str) {
                    push(id, &mut out, &mut seen);
                }
            }
            break;
        }
    }
    // 2. 补齐 data.models 里其余可对话模型
    for id in meta_by_id.keys() {
        push(id, &mut out, &mut seen);
    }
    // 3. 试用模型（既不在 craft 也不在 data.models，仅由试用横幅下发）
    if let Some(banners) = data
        .get("productFeaturesConfig")
        .and_then(|value| value.get("ModelTrialBanner"))
        .and_then(|value| value.get("banners"))
        .and_then(Value::as_array)
    {
        for banner in banners {
            if let Some(id) = banner.get("targetModelId").and_then(Value::as_str) {
                push(id, &mut out, &mut seen);
            }
        }
    }
    out
}

/// 当前清单（缓存优先，其次快照）。
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

/// 拉一次 `/v3/config` 并落地。
pub async fn refresh(
    client: &reqwest::Client,
    access_token: &str,
    force: bool,
) -> proto::RefreshOutcome {
    let now = http::now_ms();
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
    let url = format!("{}{}", BUDDY.endpoint, CONFIG_PATH);
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {access_token}")),
        ("User-Agent".to_string(), BUDDY.user_agent.to_string()),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    let (status, payload) = match http::get_json(client, &url, &headers).await {
        Ok(result) => result,
        Err(error) => return proto::RefreshOutcome::failed(error),
    };
    if !(200..300).contains(&status) {
        return proto::RefreshOutcome::failed(format!(
            "CodeBuddy 模型配置请求失败（HTTP {status}）"
        ));
    }
    let models = parse_config(&payload);
    if models.is_empty() {
        return proto::RefreshOutcome::failed(
            "CodeBuddy 模型配置为空或格式不认识（保留现有清单）",
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
