//! TeleAgent 的模型清单：**静态 5 条**（上游没有可查的目录接口）。
//!
//! ── 数据来源 ──────────────────────────────────────────────
//! 两个互相印证的来源（2026-11 抓取）：
//!   1. 参考实现 `anbulang/opencode-teleagent-auth` 的 `lib/models.mjs`；
//!   2. 桌面端自己的账号配置 `~/.config/TeleAgent/users/<scope>/TeleAgent.jsonc`
//!      的 `provider.NewApi.models` —— 那是客户端真正在用的目录，本机实测
//!      （客户端 3.0.0）上下文 / 输出上限与此处逐条一致。
//!
//! | 模型 | 展示名 | 上下文 | 输出上限 | 工具调用 | 图片 | 积分倍率 |
//! |---|---|---|---|---|---|---|
//! | `chat-pro` | 智能 | 400K | 65,536 | ✓ | ✓ | x0.6 |
//! | `chat-flagship` | 旗舰 | 400K | 65,536 | ✓ | ✗ | x1.0 |
//! | `chat-flash` | 极速 | 400K | 65,536 | ✓ | ✓ | x0.2 |
//! | `chat-lite` | 轻量 | 100K | 16,384 | ✓ | ✗ | x0.5 |
//! | `chat-nano` | 轻速 | 100K | 16,384 | ✓ | ✗ | x0.1 |
//!
//! ⚠️ 客户端配置里还有第 6 条 `tele-safety-answer`（100K / 16384）：那是内容
//! 安全过滤用的内部模型，参考实现与官方目录都不把它当可用模型，这里**不列**
//! —— 列上去等于给用户一个点了会被上游当安全链路线用的名字。
//!
//! ── 图片能力是**实测**结论，不是目录声明 ──────────────────────
//! 用同一张「蓝色三角形 + 文字 42」逐个试（参考实现）：`chat-pro` / `chat-flash`
//! 正确识别；`chat-lite` 回 200 但答非所问；`chat-nano` 回 400
//! 「is not a multimodal model」；`chat-flagship` 回 1210。客户端自己的目录把
//! `chat-pro` / `chat-flash` 标成 `Input.Image:false`，与实测不符 —— **以实测为准**。
//!
//! ── 输出上限的意义 ────────────────────────────────────────
//! 上游对超限的 `max_tokens` 直接报错（不像别家会静默钳制），所以清单里这个值
//! 是要拿去**封顶**的（见 `mod.rs` 的 `clamp_max_tokens`）。
//!
//! ── 模型 id 的两种形态（要注意）──────────────────────────────
//! 有的部署下发裸名（`chat-pro`），有的带渠道前缀（`NewApi/chat-pro`）。
//! 插件**原样透传**：用户在客户端写什么就发什么，不做拆分或加前缀 —— 猜错了
//! 只会换来上游「模型不存在」，而那种报错看不出是前缀问题。

use serde_json::{json, Value};

/// 一个模型的静态声明。
pub struct Model {
    pub id: &'static str,
    pub name: &'static str,
    pub context: u64,
    pub max_output: u64,
    pub supports_tools: bool,
    pub supports_reasoning: bool,
    pub supports_image: bool,
    /// 积分消耗倍率（厂商自己的写法，如 `x0.6`）。
    pub rate: &'static str,
}

/// 静态模型表（顺序即界面顺序，`chat-pro` 放第一位当默认首选）。
pub const MODELS: &[Model] = &[
    Model {
        id: "chat-pro",
        name: "智能",
        context: 400_000,
        max_output: 65_536,
        supports_tools: true,
        supports_reasoning: true,
        supports_image: true,
        rate: "x0.6",
    },
    Model {
        id: "chat-flagship",
        name: "旗舰",
        context: 400_000,
        max_output: 65_536,
        supports_tools: true,
        supports_reasoning: true,
        supports_image: false,
        rate: "x1.0",
    },
    Model {
        id: "chat-flash",
        name: "极速",
        context: 400_000,
        max_output: 65_536,
        supports_tools: true,
        supports_reasoning: true,
        supports_image: true,
        rate: "x0.2",
    },
    Model {
        id: "chat-lite",
        name: "轻量",
        context: 100_000,
        max_output: 16_384,
        supports_tools: true,
        supports_reasoning: false,
        supports_image: false,
        rate: "x0.5",
    },
    Model {
        id: "chat-nano",
        name: "轻速",
        context: 100_000,
        max_output: 16_384,
        supports_tools: true,
        supports_reasoning: false,
        supports_image: false,
        rate: "x0.1",
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
                // 思考走**独立 delta 字段**，不是正文标签（2026-11 实测）：
                // `chat-nano` 叫 `delta.reasoning`，其余叫 `delta.reasoning_content`。
                // 这一位只用于界面提示与探测脚本，不参与请求构造。
                "supportsReasoning": model.supports_reasoning,
                "supportsImage": model.supports_image,
                "rate": model.rate,
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

/// 这个模型 id 在不在目录里（本机导入的账号会用到：目录外的 id 上游会**静默
/// 回落**到别的模型，所以要在本地就拦住）。
pub fn is_known(model: &str) -> bool {
    let bare = model.rsplit('/').next().unwrap_or(model).trim();
    MODELS.iter().any(|known| known.id == bare)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_declares_five_models_with_their_caps() {
        let models = list();
        assert_eq!(models.len(), 5);
        assert_eq!(models[0]["id"], "chat-pro");
        assert_eq!(models[0]["context"], 400_000);
        assert_eq!(models[0]["maxTokens"], 65_536);
        // 图片能力是实测结论：只有 pro / flash 支持
        let image: Vec<&str> = models
            .iter()
            .filter(|model| model["supportsImage"] == json!(true))
            .filter_map(|model| model["id"].as_str())
            .collect();
        assert_eq!(image, vec!["chat-pro", "chat-flash"]);
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
        assert_eq!(max_output_of("tele-safety-answer"), None);
    }

    /// 目录外的模型 id 要能拦住（上游对未知 id 会静默回落到别的模型）。
    #[test]
    fn out_of_catalogue_models_are_rejected() {
        assert!(is_known("chat-pro"));
        assert!(is_known("NewApi/chat-flash"));
        assert!(!is_known("chat-ultra"));
        assert!(!is_known("gpt-5"));
    }
}
