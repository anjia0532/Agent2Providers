//! OrcaRouter 的**上游参数怪癖**：哪些模型拒收 `temperature`、哪些要钉死采样值。
//!
//! ── 为什么需要这一层 ────────────────────────────────────────
//! OrcaRouter 是个 meta-router：同一个 API key 会被它转发到 OpenAI / Anthropic /
//! Google / DeepSeek / Qwen / Kimi 等多家上游。其中有几家**拒收**通用 OpenAI
//! 请求体里的字段，直接发就是 HTTP 400。所以出站前要按模型 id 做一遍修剪。
//!
//! ── 判据来源 ──────────────────────────────────────────────
//! 逐条照抄官方 AI SDK（`Continuum-AI-Corp/orcarouter-ai-sdk` 的 `src/quirks.ts`，
//! 该文件注明 "Confirmed against the live OrcaRouter API"）。**不要凭直觉加前缀规则** ——
//! 原文件特意写明：只有 Opus 4.7/4.8 与 Fable 5 这几代拒收 temperature，
//! 更早的 Opus 4.x 正常接受，所以用 `claude-opus-4.` 这种宽前缀会**静默丢掉一个
//! 本来可用的参数**。

/// 该模型的上游会拒收 `temperature`（HTTP 400）。
///
/// 包含**所有** `orcarouter/` 虚拟路由：路由器逐请求挑上游，可能落到某个
/// 拒收 temperature 的推理模型上，所以整个命名空间一律不发。
pub fn rejects_temperature(model: &str) -> bool {
    model.starts_with("orcarouter/")
        || model.starts_with("anthropic/claude-opus-4.7")
        || model.starts_with("anthropic/claude-opus-4.8")
        || model.starts_with("anthropic/claude-fable-5")
        || model.starts_with("openai/gpt-5")
        || is_deepseek_reasoner(model)
}

/// DeepSeek 的 r1 / reasoner 系列：自动思考，且拒收推理控制字段与非默认 `temperature`。
pub fn is_deepseek_reasoner(model: &str) -> bool {
    model == "deepseek/deepseek-reasoner" || model.starts_with("deepseek/deepseek-r1")
}

/// Kimi K2.6 只接受固定的 `temperature = 1` 与 `top_p = 0.95`。
pub fn requires_fixed_sampling(model: &str) -> bool {
    model.starts_with("kimi/kimi-k2.6")
}

/// Kimi K2.6 要求的固定采样值。
pub const KIMI_TEMPERATURE: f64 = 1.0;
/// Kimi K2.6 要求的固定 `top_p`。
pub const KIMI_TOP_P: f64 = 0.95;

/// 按模型 id 修剪出站请求体（就地修改）。
///
/// 只在命中的模型上动字段：**不改没命中模型的任何东西** —— 一个「反正无害」
/// 的全局改写会悄悄改掉用户明确设置的采样参数。
pub fn apply(body: &mut serde_json::Value) {
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let model = object
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    if model.is_empty() {
        return;
    }
    if rejects_temperature(&model) {
        object.remove("temperature");
    }
    if requires_fixed_sampling(&model) {
        object.insert("temperature".to_string(), serde_json::json!(KIMI_TEMPERATURE));
        object.insert("top_p".to_string(), serde_json::json!(KIMI_TOP_P));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 整个 `orcarouter/` 命名空间都不发 temperature（含免费档与融合档）。
    #[test]
    fn every_virtual_router_drops_temperature() {
        for model in ["orcarouter/auto", "orcarouter/free", "orcarouter/pod", "orcarouter/fusion"] {
            assert!(rejects_temperature(model), "{model} 应当拒收 temperature");
        }
    }

    /// 只有 4.7/4.8 与 Fable 5 这几代拒收；更早的 Opus 4.x **正常接受**。
    ///
    /// 这条是原文件特意点出的坑：用 `claude-opus-4.` 这种宽前缀会把 opus-4.5/4.6
    /// 的 temperature 一起丢掉，而那些模型本来收这个参数。
    #[test]
    fn older_opus_generations_still_accept_temperature() {
        assert!(rejects_temperature("anthropic/claude-opus-4.7"));
        assert!(rejects_temperature("anthropic/claude-opus-4.8"));
        assert!(rejects_temperature("anthropic/claude-fable-5.1"));
        assert!(!rejects_temperature("anthropic/claude-opus-4.5"), "4.5 接受 temperature，不能丢");
        assert!(!rejects_temperature("anthropic/claude-opus-4.6"), "4.6 接受 temperature，不能丢");
        assert!(!rejects_temperature("anthropic/claude-sonnet-5"), "Sonnet 不在此列");
    }

    /// gpt-5 家族与 deepseek 推理系列都在列。
    #[test]
    fn gpt5_and_deepseek_reasoner_are_covered() {
        assert!(rejects_temperature("openai/gpt-5"));
        assert!(rejects_temperature("openai/gpt-5.2-mini"));
        assert!(rejects_temperature("deepseek/deepseek-reasoner"));
        assert!(rejects_temperature("deepseek/deepseek-r1-0528"));
        assert!(!rejects_temperature("deepseek/deepseek-chat"));
    }

    /// Kimi K2.6 被钉到固定采样值，其余模型不动。
    #[test]
    fn kimi_k26_gets_pinned_sampling_and_others_are_untouched() {
        let mut kimi = json!({ "model": "kimi/kimi-k2.6", "temperature": 0.2, "top_p": 0.3 });
        apply(&mut kimi);
        assert_eq!(kimi["temperature"], json!(1.0));
        assert_eq!(kimi["top_p"], json!(0.95));

        let mut other = json!({ "model": "anthropic/claude-sonnet-5", "temperature": 0.2 });
        apply(&mut other);
        assert_eq!(other["temperature"], json!(0.2), "没命中的模型一个字段都不该动");
    }

    /// 修剪只删 `temperature`，不顺手删别的采样字段。
    #[test]
    fn stripping_temperature_leaves_other_fields_alone() {
        let mut body = json!({
            "model": "orcarouter/free",
            "temperature": 0.7,
            "top_p": 0.9,
            "max_tokens": 64,
            "messages": []
        });
        apply(&mut body);
        assert!(body.get("temperature").is_none(), "temperature 应当被删");
        assert_eq!(body["top_p"], json!(0.9), "top_p 不该被牵连");
        assert_eq!(body["max_tokens"], json!(64));
        assert!(body.get("messages").is_some());
    }

    /// 没有 model 字段（畸形请求体）时不动，也不 panic。
    #[test]
    fn a_body_without_a_model_is_left_alone() {
        let mut body = json!({ "temperature": 0.5 });
        apply(&mut body);
        assert_eq!(body["temperature"], json!(0.5));
    }
}
