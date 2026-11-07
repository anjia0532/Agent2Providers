//! MiniMax 模型目录：`GET {apiHost}/mavis/api/v1/models?region=&buildEnv=prod`
//! + 进程缓存 + **远端快照兜底**。
//!
//! ── 上游形态（两站同形，2026-10-15 真机实测）──────────────────
//! ```text
//! GET https://agent.minimax.io/mavis/api/v1/models?region=en&buildEnv=prod
//!   → {"providers":[{"providerId":"minimax","config":{
//!        "model_order":["MiniMax-M3.1-Flash-Preview", …],
//!        "models":{"MiniMax-M3.1-Flash-Preview":{
//!           "name":"M3.1-Flash-Preview",
//!           "limit":{"context":512000,"output":128000},
//!           "context_window_options":[512000,1000000],
//!           "modalities":{"input":["text","image"]},
//!           "effort_options":["default","low","medium","high","xhigh","max"],
//!           "default_effort":"default",
//!           "thinking_config":{"mode":"forced_on"}}}, …}}}]}
//! ```
//!
//! ── 三条归一规则（与官方客户端同源）──────────────────────────
//!   · **窗口**取 `context_window_options` 的**最大档**（不是 `limit.context`：
//!     M3.1-Flash-Preview 的 `limit.context` 是 512K，而档位表是 `[512K, 1M]`，
//!     填 512K 会让压缩远早于官方能力触发）；
//!   · **输出上限**取 `limit.output`，只放行安全正整数；
//!   · **是否收图**看 `modalities.input` 含不含 `image`。
//!
//! ── 兜底表必须含 M3.1-Flash-Preview ──────────────────────────
//! 它**不在**客户端内置静态表里（asar 只有 M3 / M2.7-highspeed / M2.7）。
//! 漏掉它，远端一失败用户就看不到自己在用的模型。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;

use super::region::Region;
use crate::http;

/// 目录路径（相对 API 主机）
pub const MODELS_PATH: &str = "/mavis/api/v1/models";

/// 构建环境（目录查询参数）
pub const BUILD_ENV: &str = "prod";

/// 自动路径的缓存 TTL（与各家同档）
const TTL_MS: i64 = 10 * 60 * 1000;

/// 兜底模型条目：`[id, 展示名, 上下文窗口, 输出上限, 收图, 思考模式, 档位表]`
type Fallback = (&'static str, &'static str, u64, u64, bool, &'static str, &'static [&'static str]);

/// 兜底模型表（4 条，顺序**照抄远端 `model_order`**）。
///
/// ⚠️ 只有 M3.1-Flash-Preview 有档位表 —— 其余三个远端**没有 `effort_options`**，
/// 给它们编档位就是凭空猜测。
const FALLBACK: &[Fallback] = &[
    (
        "MiniMax-M3.1-Flash-Preview",
        "M3.1-Flash-Preview",
        1_000_000,
        128_000,
        true,
        "forced_on",
        &["default", "low", "medium", "high", "xhigh", "max"],
    ),
    ("MiniMax-M3", "M3", 1_000_000, 128_000, true, "switchable", &[]),
    (
        "MiniMax-M2.7-highspeed",
        "M2.7-highspeed",
        200_000,
        128_000,
        false,
        "forced_on",
        &[],
    ),
    ("MiniMax-M2.7", "M2.7", 200_000, 128_000, false, "forced_on", &[]),
];

/// 进程内缓存（两个站点各一份：两站目录互不覆盖）
struct CatalogState {
    models: Vec<Value>,
    fetched_at: i64,
}

static STATE_CN: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();
static STATE_INTL: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();

fn state(region: Region) -> &'static Mutex<Option<CatalogState>> {
    match region {
        Region::Cn => STATE_CN.get_or_init(|| Mutex::new(None)),
        Region::Intl => STATE_INTL.get_or_init(|| Mutex::new(None)),
    }
}

fn with_state<R>(region: Region, f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mut guard = state(region)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 思考模式（决定「能否关闭思考」）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThinkingMode {
    /// 强制开启：传 `disabled` 会被静默忽略或硬 400
    ForcedOn,
    /// 可开关：不传不思考，传 `adaptive` 思考
    Switchable,
}

impl ThinkingMode {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "forced_on" => Some(ThinkingMode::ForcedOn),
            "switchable" => Some(ThinkingMode::Switchable),
            _ => None,
        }
    }
}

/// 一条归一后的模型条目（供 `reasoning_patch` 与 `models` 共用）。
///
/// 只保留**思考决策真正要读的字段**：窗口/输出上限/收图这三项在对外模型对象里
/// 已有（`context` / `maxTokens` / `supportsImage`），`reasoning_patch` 不读它们，
/// 抄一份进内部结构只会变成永远不同步的死字段。
#[derive(Clone, Debug)]
pub struct ModelEntry {
    pub id: String,
    pub thinking_mode: Option<ThinkingMode>,
    pub effort_options: Vec<String>,
    pub default_effort: Option<String>,
}

impl ModelEntry {
    /// M3.1-Flash-Preview：**必须** adaptive，传 `disabled` 会硬 400（实测 2013）
    pub fn requires_adaptive_thinking(&self) -> bool {
        self.thinking_mode == Some(ThinkingMode::ForcedOn) && !self.effort_options.is_empty()
    }

    /// 这个模型**关得掉**思考（switchable）
    pub fn can_disable_thinking(&self) -> bool {
        self.thinking_mode == Some(ThinkingMode::Switchable)
    }
}

/// 兜底表转条目（**直接搬运字面量**，不再归一：值是人工按实测口径填好的）。
fn fallback_entry(
    id: &str,
    name: &str,
    context_window: u64,
    max_tokens: u64,
    supports_image: bool,
    mode: &str,
    efforts: &[&str],
) -> (ModelEntry, Value) {
    let entry = ModelEntry {
        id: id.to_string(),
        thinking_mode: ThinkingMode::parse(mode),
        effort_options: efforts.iter().map(|item| item.to_string()).collect(),
        default_effort: None,
    };
    let mut model = json!({
        "id": id,
        "name": name,
        "supportsToolCall": true,
        "supportsImage": supports_image,
    });
    if context_window > 0 {
        model["context"] = json!(context_window);
    }
    if max_tokens > 0 {
        model["maxTokens"] = json!(max_tokens);
    }
    if !efforts.is_empty() {
        model["reasoning"] = json!({ "efforts": efforts });
    }
    (entry, model)
}

/// 兜底表（条目 + 对外模型对象）
pub fn fallback() -> (Vec<ModelEntry>, Vec<Value>) {
    let mut entries = Vec::with_capacity(FALLBACK.len());
    let mut models = Vec::with_capacity(FALLBACK.len());
    for (id, name, context_window, max_tokens, image, mode, efforts) in FALLBACK {
        let (entry, model) = fallback_entry(id, name, *context_window, *max_tokens, *image, mode, efforts);
        entries.push(entry);
        models.push(model);
    }
    (entries, models)
}

/// 按 id 在兜底表里查一条（`reasoning_patch` 用）
pub fn fallback_entry_of(id: &str) -> Option<ModelEntry> {
    FALLBACK
        .iter()
        .find(|(fallback_id, ..)| *fallback_id == id)
        .map(|(id, _name, _context_window, _max_tokens, _image, mode, efforts)| ModelEntry {
            id: id.to_string(),
            thinking_mode: ThinkingMode::parse(mode),
            effort_options: efforts.iter().map(|item| item.to_string()).collect(),
            default_effort: None,
        })
}

fn positive_int(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|raw| u64::try_from(raw).ok()))
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
}

fn string_array(value: &Value) -> Option<Vec<String>> {
    let rows = value.as_array()?;
    let mut out: Vec<String> = Vec::new();
    for item in rows {
        let Some(text) = item.as_str().map(str::trim).filter(|text| !text.is_empty()) else {
            continue;
        };
        if !out.iter().any(|known| known == text) {
            out.push(text.to_string());
        }
    }
    (!out.is_empty()).then_some(out)
}

/// 归一一条远端条目（规则见模块头）。
fn normalize(id: &str, raw: &Value) -> Option<(ModelEntry, Value)> {
    let name = raw
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .unwrap_or(id)
        .to_string();
    let limit = raw.get("limit").and_then(Value::as_object);
    let context_window = raw
        .get("context_window_options")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .filter_map(positive_int)
                .max()
        })
        .or_else(|| limit.and_then(|object| object.get("context")).and_then(positive_int))
        .unwrap_or(0);
    let max_tokens = limit
        .and_then(|object| object.get("output"))
        .and_then(positive_int)
        .unwrap_or(0);
    let supports_image = raw
        .get("modalities")
        .and_then(|value| value.get("input"))
        .and_then(Value::as_array)
        .map(|rows| rows.iter().any(|item| item.as_str() == Some("image")))
        .unwrap_or(false);
    let effort_options = raw
        .get("effort_options")
        .and_then(string_array)
        .unwrap_or_default();
    let default_effort = raw
        .get("default_effort")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .filter(|text| effort_options.iter().any(|known| known == text))
        .map(str::to_string);
    let thinking_mode = raw
        .get("thinking_config")
        .and_then(|value| value.get("mode"))
        .and_then(Value::as_str)
        .and_then(ThinkingMode::parse);
    let entry = ModelEntry {
        id: id.to_string(),
        thinking_mode,
        effort_options: effort_options.clone(),
        default_effort,
    };
    let mut model = json!({
        "id": id,
        "name": name,
        "supportsToolCall": true,
        "supportsImage": supports_image,
    });
    if context_window > 0 {
        model["context"] = json!(context_window);
    }
    if max_tokens > 0 {
        model["maxTokens"] = json!(max_tokens);
    }
    if !effort_options.is_empty() {
        model["reasoning"] = json!({ "efforts": effort_options });
    }
    Some((entry, model))
}

/// 解析 `/models` 响应（`providers[providerId=minimax].config.models`）。
pub fn parse_payload(payload: &Value) -> (Vec<ModelEntry>, Vec<Value>) {
    let Some(providers) = payload.get("providers").and_then(Value::as_array) else {
        return (Vec::new(), Vec::new());
    };
    let Some(config) = providers
        .iter()
        .find(|provider| provider.get("providerId").and_then(Value::as_str) == Some("minimax"))
        .and_then(|provider| provider.get("config"))
        .and_then(Value::as_object)
    else {
        return (Vec::new(), Vec::new());
    };
    let Some(models) = config.get("models").and_then(Value::as_object) else {
        return (Vec::new(), Vec::new());
    };
    let mut entries: Vec<(usize, ModelEntry, Value)> = models
        .iter()
        .filter_map(|(id, raw)| normalize(id, raw).map(|(entry, model)| (0, entry, model)))
        .collect();
    // 按远端 model_order 排序（若提供），否则保持对象插入序
    if let Some(order) = config.get("model_order").and_then(Value::as_array) {
        let index: std::collections::HashMap<&str, usize> = order
            .iter()
            .enumerate()
            .filter_map(|(position, id)| id.as_str().map(|id| (id, position)))
            .collect();
        for item in &mut entries {
            item.0 = index.get(item.1.id.as_str()).copied().unwrap_or(usize::MAX);
        }
        entries.sort_by_key(|(position, _, _)| *position);
    }
    let mut out_entries = Vec::with_capacity(entries.len());
    let mut out_models = Vec::with_capacity(entries.len());
    for (_, entry, model) in entries {
        out_entries.push(entry);
        out_models.push(model);
    }
    (out_entries, out_models)
}

/// 当前模型清单（内存缓存；没有时回落到快照）。
pub fn list(region: Region) -> proto::ModelList {
    let cached = with_state(region, |slot| {
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
    let (_, models) = fallback();
    proto::ModelList {
        models,
        meta: proto::CatalogMeta {
            // 快照不是远端拉的，如实标记
            remote: false,
            refreshed_at: 0,
        },
    }
}

/// 按 id 查一条（缓存优先，其次快照）。
///
/// 缓存里存的是**对外模型对象**，`reasoning_patch` 需要的只有「有没有档位表」，
/// 所以从对外对象里读，不再单独存一份内部形态（少一处要同步的事实）。
pub fn find(region: Region, id: &str) -> Option<ModelEntry> {
    let cached = with_state(region, |slot| {
        slot.as_ref().and_then(|state| {
            state.models.iter().find(|model| {
                model.get("id").and_then(Value::as_str) == Some(id)
            })?;
            state_entries(state)?.into_iter().find(|entry| entry.id == id)
        })
    });
    if cached.is_some() {
        return cached;
    }
    fallback_entry_of(id)
}

/// 从缓存的对外模型对象里反解条目（缓存只存对外对象，条目按需重建）。
///
/// 缓存里**没有**存 `ModelEntry`（那是内部形态，落缓存会多一份要同步的事实）。
/// 这里按对外对象重建一份只含 `reasoning` 信息的轻量条目 —— `reasoning_patch`
/// 只需要「有没有档位表」与「思考模式」，而这两样都在对外对象里。
fn state_entries(state: &CatalogState) -> Option<Vec<ModelEntry>> {
    let entries = state
        .models
        .iter()
        .map(|model| ModelEntry {
            id: model
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            thinking_mode: None,
            effort_options: model
                .get("reasoning")
                .and_then(|value| value.get("efforts"))
                .and_then(Value::as_array)
                .and_then(|rows| {
                    let mut out: Vec<String> = Vec::new();
                    for row in rows {
                        if let Some(text) = row.as_str().map(str::trim).filter(|t| !t.is_empty()) {
                            if !out.iter().any(|known| known == text) {
                                out.push(text.to_string());
                            }
                        }
                    }
                    (!out.is_empty()).then_some(out)
                })
                .unwrap_or_default(),
            default_effort: None,
        })
        .collect();
    Some(entries)
}

/// 拉一次模型目录并落地（内存缓存）。
pub async fn refresh(
    region: Region,
    client: &reqwest::Client,
    access_token: &str,
    force: bool,
) -> proto::RefreshOutcome {
    let now = http::now_ms();
    if !force {
        let fresh = with_state(region, |slot| {
            slot.as_ref()
                .map(|state| !state.models.is_empty() && now - state.fetched_at < TTL_MS)
                .unwrap_or(false)
        });
        if fresh {
            return proto::RefreshOutcome::unchanged();
        }
    }
    let url = format!(
        "{}{}?region={}&buildEnv={}",
        region.api_base_url(),
        MODELS_PATH,
        region.region(),
        BUILD_ENV
    );
    let headers = vec![("Authorization".to_string(), format!("Bearer {access_token}"))];
    let (status, payload) = match http::get_json(&client, &url, &headers).await {
        Ok(result) => result,
        Err(error) => return proto::RefreshOutcome::failed(error),
    };
    if !(200..300).contains(&status) {
        return proto::RefreshOutcome::failed(format!(
            "MiniMax 模型目录请求失败（HTTP {status}）"
        ));
    }
    let (_, models) = parse_payload(&payload);
    if models.is_empty() {
        return proto::RefreshOutcome::failed(
            "MiniMax 模型目录为空或格式不认识（保留现有清单）",
        );
    }
    let count = models.len();
    with_state(region, |slot| {
        *slot = Some(CatalogState {
            models: models.clone(),
            fetched_at: now,
        });
    });
    proto::RefreshOutcome::refreshed(count)
}
