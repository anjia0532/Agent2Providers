//! MiniMax Code 的两个站点：**一份实现、两个实例**。
//!
//! ── 为什么是两个 provider 而不是一个 provider 加区域参数 ────────
//! 两个站点**账号不互通**（国内平台与国际平台是两套账号），且模型目录按
//! provider 缓存一份 —— 做成区域参数会让两站目录互相覆盖。这与
//! `qoder` / `qwenwork` / `autoclaw` 的双 id 方案同型。
//!
//! ── 两站只差这几个字段，其余逐字段相同 ────────────────────────
//! | 字段 | 国内版 | 国际版 |
//! |---|---|---|
//! | `id` | `minimax` | `minimaxintl` |
//! | 展示名 | `MiniMax Code (中国版)` | `MiniMax Code (国际版)` |
//! | accountHost | `account.minimax.cn` | `account.minimax.io` |
//! | apiHost | `agent.minimax.cn` | `agent.minimax.io` |
//! | region | `cn` | `en` |
//!
//! ⇒ 因此**不复制任何实现文件**：适配器 / OAuth / 目录 / 积分全部共用，
//! 差异只在本文件的常量里。

/// 站点（一个 provider 一个实例）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    /// 国内版（`account.minimax.cn` / `agent.minimax.cn`）
    Cn,
    /// 国际版（`account.minimax.io` / `agent.minimax.io`）
    Intl,
}

impl Region {
    /// provider id（`pack.json` 里也要写同一个）。
    pub fn provider_id(self) -> &'static str {
        match self {
            Region::Cn => "minimax",
            Region::Intl => "minimaxintl",
        }
    }

    /// 展示名（**必须带括注**，否则用户分不清哪个是国内站）。
    pub fn label(self) -> &'static str {
        match self {
            Region::Cn => "MiniMax Code 中国版",
            Region::Intl => "MiniMax Code 国际版",
        }
    }

    /// 账号与 OAuth 主机（`https://` 开头，不含尾斜杠）。
    pub fn account_base_url(self) -> &'static str {
        match self {
            Region::Cn => "https://account.minimax.cn",
            Region::Intl => "https://account.minimax.io",
        }
    }

    /// API 主机（目录 / 签到 / 积分 / 推理）。
    pub fn api_base_url(self) -> &'static str {
        match self {
            Region::Cn => "https://agent.minimax.cn",
            Region::Intl => "https://agent.minimax.io",
        }
    }

    /// 目录查询参数 `region`（**按站点不同**：国内 `cn` / 国际 `en`）。
    pub fn region(self) -> &'static str {
        match self {
            Region::Cn => "cn",
            Region::Intl => "en",
        }
    }

    /// OAuth client_id（官方常量，两站相同）。
    pub fn client_id(self) -> &'static str {
        "mcode-public"
    }

    /// OAuth audience（官方常量，两站相同）。
    pub fn audience(self) -> &'static str {
        "agent-backend"
    }

    /// OAuth scope（**凭据校验要求必须含它**，否则 `invalid_token_response`）。
    pub fn scope(self) -> &'static str {
        super::SCOPE
    }
}
