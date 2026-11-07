//! 七牛云模型目录：`GET {base}/models`（标准 OpenAI 形态）+ 进程缓存 + **远端快照兜底**。
//!
//! ── 上游形态（2026-10-29 直连实测）────────────────────────────
//! ```text
//! GET https://api.qnaigc.com/v1/models        Authorization: Bearer <API Key>
//!   → {"data":[{"id":"deepseek/deepseek-v4-pro-0813","object":"model",
//!              "owned_by":"deepseek","created":…,"context_length":1000000,
//!              "max_tokens":…}, …]}
//! ```
//!
//! ── 三个必须知道的实测事实 ────────────────────────────────────
//! 1. **`/models` 免鉴权也回 200** ⇒ 「目录能读到」**不能**用来判凭据有效性；
//! 2. **模型 id 由平台动态下发**，且是**两种形态混合**：新模型带厂商命名空间
//!    前缀（`moonshotai/kimi-k3`、`deepseek/deepseek-v4-pro-0813`、
//!    `qwen/qwen3.8-max`、`z-ai/glm-5.3`、`qiniu/conatus-free` …），
//!    老模型是裸名（`deepseek-v3`、`kimi-k2`、`glm-4.5`、`qwen-turbo` …）。
//!    **两种都原样透传** —— 官方 FAQ 明确要求请求里的 `model` 与模型广场的
//!   「API model 参数」逐字一致，自己做 `/` 拆分或归一就是把它改坏；
//! 3. **不下发模态**（无 `modalities` / `input_modalities` 字段）。
//!
//! ── 为什么必须有一张非空兜底表（与「官方说别写死」不冲突）──────
//! 官方要求的是「请求里的 model 与模型广场逐字一致」，那禁止的是**拆分/归一
//! id**，并不禁止本地留一份离线快照。而把兜底表置空的代价是实测出来的：
//! 冷缓存时目录恒空 ⇒ 面板把该渠道**误显示为「已关闭且无模型可关」**，
//! 模型选择器里一个模型都没有。
//!
//! 因此：**远端永远优先**，快照只承接「远端不可用且无缓存」的兜底。
//! 下表是 2026-10-29 直连 `/v1/models` 的实测快照（id + `context_length`）。

use std::sync::{Mutex, OnceLock};

use serde_json::{json, Value};

use agent2api_provider_protocol as proto;

use crate::http;

/// 模型列表路径（相对 base，base 已含 `/v1`）
pub const MODELS_PATH: &str = "/models";

/// 自动路径的缓存 TTL（与各家同档）
const TTL_MS: i64 = 10 * 60 * 1000;

/// 进程内缓存
struct CatalogState {
    models: Vec<Value>,
    fetched_at: i64,
}

static STATE: OnceLock<Mutex<Option<CatalogState>>> = OnceLock::new();

fn state() -> &'static Mutex<Option<CatalogState>> {
    STATE.get_or_init(|| Mutex::new(None))
}

/// 在锁内执行一段取值（毒锁按「继续用」处理：这份缓存是可重建的展示数据）
fn with_state<R>(f: impl FnOnce(&mut Option<CatalogState>) -> R) -> R {
    let mut guard = state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard)
}

/// 远端实测快照：`[id, context_length]`。
///
/// `context_length` 为 0 表示「不知道」（不下发 `context`），**不是**合法窗口。
const REMOTE_SNAPSHOT: &[(&str, u64)] = &[
    ("meituan/longcat-flash-lite", 256_000),
    ("qwen3-vl-30b-a3b-thinking", 128_000),
    ("doubao-1.5-pro-32k", 128_000),
    ("doubao-1.5-thinking-pro", 128_000),
    ("doubao-1.5-vision-pro", 128_000),
    ("glm-4.5", 131_072),
    ("kimi-k2", 128_000),
    ("qwen-turbo", 1_000_000),
    ("qwen-vl-max-2025-01-25", 128_000),
    ("qwen2.5-vl-72b-instruct", 128_000),
    ("qwen3-235b-a22b", 128_000),
    ("qwen3-30b-a3b", 40_000),
    ("qwen3-235b-a22b-instruct-2507", 262_144),
    ("qwen3-235b-a22b-thinking-2507", 262_144),
    ("qwen3-coder-480b-a35b-instruct", 262_000),
    ("doubao-seed-1.6", 256_000),
    ("doubao-seed-1.6-flash", 256_000),
    ("doubao-seed-1.6-thinking", 256_000),
    ("qwen3-next-80b-a3b-thinking", 131_072),
    ("qwen3-next-80b-a3b-instruct", 131_072),
    ("z-ai/glm-4.6", 200_000),
    ("moonshotai/kimi-k2-thinking", 256_000),
    ("z-ai/glm-4.7", 200_000),
    ("qwen3-30b-a3b-thinking-2507", 126_000),
    ("tencent/hy3-preview", 262_144),
    ("qwen/qwen3.6-27b", 262_100),
    ("nvidia/nemotron-3-ultra-550b-a55b0-free", 1_000_000),
    ("moonshotai/kimi-k3-free", 1_048_576),
    ("z-ai/glm-5.1", 200_000),
    ("moonshotai/kimi-k2.6", 262_000),
    ("qwen/qwen3.7-max", 1_000_000),
    ("minimax/minimax-m3", 1_000_000),
    ("moonshotai/kimi-k2.7-code", 262_144),
    ("z-ai/glm-5.2", 1_000_000),
    ("qwen/qwen3.7-plus", 1_000_000),
    ("bytedance/doubao-seed-2-1-pro", 256_000),
    ("bytedance/doubao-seed-2-1-turbo", 256_000),
    ("stepfun/step-3.7-flash", 256_000),
    ("moonshotai/kimi-k3", 1_048_576),
    ("deepseek/deepseek-v4-flash-20260731", 1_000_000),
    ("qwen/qwen3.8-max", 1_000_000),
    ("deepseek/deepseek-v4-pro-0813", 1_000_000),
    ("z-ai/glm-5.3", 1_000_000),
    ("deepseek/deepseek-v4-flash-vision-exp", 1_000_000),
    ("qwen/qwen3.8-flash-next", 1_000_000),
    ("z-ai/glm-5.3-flash", 1_000_000),
    ("tencent/hy4-preview", 1_000_000),
    ("deepseek/deepseek-v4.1-flash", 1_000_000),
    ("qwen/qwen3.7-flash", 1_000_000),
    ("xiaomi/mimo-v2.6-pro", 1_000_000),
    ("xiaomi/mimo-v2.6-flash", 1_000_000),
    ("bytedance/doubao-seed-2-1-lite", 1_024_000),
    ("deepseek/deepseek-v4.1-flash-1017", 1_000_000),
    ("minimax/minimax-m3.1-flash", 1_000_000),
    ("qiniu/conatus-free", 1_000_000),
    ("moonshotai/kimi-k3.1-pro", 1_048_576),
    ("moonshotai/kimi-k3.1-pro-highspeed", 1_048_576),
    ("doubao-seed-2.0-code", 256_000),
    ("doubao-seed-2.0-pro", 256_000),
    ("minimax/minimax-m2.5-highspeed", 204_800),
    ("MiniMax-M1", 1_000_000),
    ("doubao-seed-2.0-mini", 256_000),
    ("minimax/minimax-m2", 200_000),
    ("moonshotai/kimi-k2.5", 256_000),
    ("minimax/minimax-m2.5", 204_800),
    ("minimax/minimax-m2.7", 204_800),
    ("doubao-seed-2.0-lite", 256_000),
    ("qwen3.5-397b-a17b", 256_000),
    ("qwen-max-2025-01-25", 128_000),
    ("qwen3-32b", 40_000),
    ("qwen3-max-preview", 256_000),
    ("qwen3-30b-a3b-instruct-2507", 128_000),
    ("minimax/minimax-m2.1", 204_800),
    ("z-ai/glm-5", 200_000),
    ("qwen3-max", 262_144),
    ("qwen/qwen3.6-plus", 1_000_000),
    ("qwen/qwen3.5-plus", 1_000_000),
];

/// 由快照构造一条模型条目。
///
/// `name` 直接用 id：远端不下发人类可读名，编一个反而与模型广场对不上
/// （用户按名字搜不到）。`context_length > 0` 才写 `context`。
fn from_snapshot(id: &str, context_length: u64) -> Value {
    let mut model = json!({
        "id": id,
        "name": id,
        "supportsToolCall": true,
    });
    if context_length > 0 {
        model["context"] = json!(context_length);
    }
    model
}

/// 把一个 OpenAI 目录条目映射成聚合层认的形态。
///
/// 只认 `id`（上游不给 `name`）；**原样透传，不拆分命名空间前缀**。
fn map_entry(row: &Value) -> Option<Value> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    let context_length = row
        .get("context_length")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(from_snapshot(id, context_length))
}

/// 解析 `/models` 响应（OpenAI `{data:[...]}` 或裸数组）
pub fn parse_models(payload: &Value) -> Vec<Value> {
    let rows = payload
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| payload.as_array())
        .cloned()
        .unwrap_or_default();
    rows.iter().filter_map(map_entry).collect()
}

/// 兜底清单（远端快照）
pub fn fallback_models() -> Vec<Value> {
    REMOTE_SNAPSHOT
        .iter()
        .map(|(id, context_length)| from_snapshot(id, *context_length))
        .collect()
}

/// 当前模型清单（内存缓存；没有时回落到快照）。
///
/// 回落而不是返回空：冷缓存即空会让面板把整个 provider 显示成「已关闭」。
pub fn list() -> proto::ModelList {
    with_state(|slot| match slot.as_ref() {
        Some(state) if !state.models.is_empty() => proto::ModelList {
            models: state.models.clone(),
            meta: proto::CatalogMeta {
                remote: true,
                refreshed_at: state.fetched_at,
            },
        },
        _ => proto::ModelList {
            models: fallback_models(),
            meta: proto::CatalogMeta {
                // 快照不是远端拉的，如实标记
                remote: false,
                refreshed_at: 0,
            },
        },
    })
}

/// 拉一次模型目录并落地（内存缓存）。
///
/// `force = false`（自动路径）时 10 分钟 TTL 内早退为 `unchanged()`；
/// `force = true`（用户手动刷新）真打上游。
///
/// 远端不可用时**保留现有清单**（与魔搭同口径）：目录是展示数据，
/// 一次网络抖动不该让界面上的模型全消失。
pub async fn refresh(client: &reqwest::Client, api_key: &str, force: bool) -> proto::RefreshOutcome {
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
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {api_key}")),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    let url = format!("{}{MODELS_PATH}", crate::providers::qiniu::BASE_URL);
    let (status, payload) = match http::get_json(client, &url, &headers).await {
        Ok(result) => result,
        // 传输层失败：保留现有清单，如实报失败（不是「空目录」）
        Err(error) => return proto::RefreshOutcome::failed(error),
    };
    if !(200..300).contains(&status) {
        return proto::RefreshOutcome::failed(format!(
            "七牛云模型目录请求失败（HTTP {status}）"
        ));
    }
    let models = parse_models(&payload);
    if models.is_empty() {
        return proto::RefreshOutcome::failed(
            "七牛云模型目录为空或格式不认识（保留现有清单）",
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
