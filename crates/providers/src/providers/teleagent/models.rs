//! TeleAgent 的模型清单：**静态 3 条**（上游没有可查的目录接口）。
//!
//! ── 数据来源 ──────────────────────────────────────────────
//! 参考实现 `T786279007/teleagent2api-deploy` 的 README 支持矩阵（2026-11 抓取），
//! 三个模型都是一手实测过的：上下文 / 输出上限 / 工具调用 / 是否产思维链。
//!
//! | 模型 | 展示名 | 上下文 | 输出上限 | 工具调用 | 思维链 |
//! |---|---|---|---|---|---|
//! | `chat-lite` | 轻量 | 100K | 16,384 | ✓ | ✗ |
//! | `chat-pro` | 旗舰 | 192K | 65,536 | ✓ | ✓ |
//! | `chat-flash` | 极速 | 192K | 65,536 | ✓ | ✗ |
//!
//! ── 模型 id 的两种形态（要注意）──────────────────────────────
//! 有的部署下发裸名（`chat-pro`），有的带渠道前缀（`NewApi/chat-pro`）。
//! 插件**原样透传**：用户在客户端写什么就发什么，不做拆分或加前缀 —— 猜错了
//! 只会换来上游「模型不存在」，而那种报错看不出是前缀问题。
//!
//! ── 输出上限的意义 ────────────────────────────────────────
//! 上游对超限的 `max_tokens` 直接报错（不像别家会静默钳制），所以清单里
//! 这个值是要拿去**封顶**的（见 `mod.rs` 的 `clamp_max_tokens`）。
//! 参考实现的「`max_tokens` 按模型封顶」这条就是为此存在。

use serde_json::{json, Value};

/// 一个模型的静态声明。
pub struct Model {
    pub id: &'static str,
    pub name: &'static str,
    pub context: u64,
    pub max_output: u64,
    pub supports_tools: bool,
    pub supports_reasoning: bool,
}

/// 静态模型表（顺序即界面顺序，`chat-pro` 放第一位当默认首选）。
pub const MODELS: &[Model] = &[
    Model {
        id: "chat-pro",
        name: "旗舰 (Chat Pro)",
        context: 192_000,
        max_output: 65_536,
        supports_tools: true,
        supports_reasoning: true,
    },
    Model {
        id: "chat-lite",
        name: "轻量 (Chat Lite)",
        context: 100_000,
        max_output: 16_384,
        supports_tools: true,
        supports_reasoning: false,
    },
    Model {
        id: "chat-flash",
        name: "极速 (Chat Flash)",
        context: 192_000,
        max_output: 65_536,
        supports_tools: true,
        supports_reasoning: false,
    },
];

/// 对外模型对象（`ProviderMeta::default_models` 的形状）。
pub fn list() -> Vec<Value> {
    MODELS
        .iter()
        .map(|model| {
            json!({
                "id": model.id,
                "name": model.name,
                "context": model.context,
                "maxTokens": model.max_output,
                "supportsToolCall": model.supports_tools,
                // 思维链是混在正文里的 `<think>` 标签，不是独立通道 —— 这一位
                // 只用于界面提示「这个模型会产思考」，不参与请求构造。
                "supportsReasoning": model.supports_reasoning,
                "supportsImage": false,
            })
        })
        .collect()
}

/// 这张模型的输出上限。
///
/// ── 为什么要按模型封顶 ────────────────────────────────────
/// 上游对超出上限的 `max_tokens` 直接回错，而不是静默钳制。客户端（尤其
/// Claude Code 那类）动辄发 128K/200K，不封顶就是「每个请求都 400」。
///
/// 认不出模型时返回 `None`（**不猜**）：调用方据此保持用户原值，让上游
/// 自己判 —— 猜一个上限反而会把用户合理的小值改大。
pub fn max_output_of(model: &str) -> Option<u64> {
    // 兼容带渠道前缀的形态（`NewApi/chat-pro`）：只看最后一段
    let bare = model.rsplit('/').next().unwrap_or(model).trim();
    MODELS
        .iter()
        .find(|known| known.id == bare)
        .map(|known| known.max_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_declares_three_models_with_their_caps() {
        let models = list();
        assert_eq!(models.len(), 3);
        assert_eq!(models[0]["id"], "chat-pro");
        assert_eq!(models[0]["context"], 192_000);
        assert_eq!(models[0]["maxTokens"], 65_536);
    }

    /// 带渠道前缀也要认出来 —— 否则「封顶」这条在最常见的部署形态下失效。
    #[test]
    fn a_prefixed_model_id_still_resolves_its_cap() {
        assert_eq!(max_output_of("chat-lite"), Some(16_384));
        assert_eq!(max_output_of("NewApi/chat-lite"), Some(16_384));
        assert_eq!(max_output_of("SomeProvider/chat-pro"), Some(65_536));
    }

    /// 认不出就不猜（返回 None 让用户原值透传）。
    #[test]
    fn an_unknown_model_has_no_cap() {
        assert_eq!(max_output_of("gpt-5"), None);
        assert_eq!(max_output_of(""), None);
    }
}
