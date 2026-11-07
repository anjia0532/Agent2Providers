//! 活动目录、账号预览与领取证据分别合并；匿名候选不扩大自动领取范围。

use std::collections::{BTreeMap, BTreeSet};

use agent2api_provider_protocol::WireProxy;
use agent2api_provider_sdk::PluginCtx;
use serde_json::{json, Value};

use crate::errors::GatewayError;
use crate::logging;

use super::plans::{merge, ClaimablePlan, OwnedPlan};
use super::super::{report_activation, region::Region};
use super::{catalog, marketing, ownership, preview_billing, state};

#[derive(Clone, Copy)]
pub enum PreviewPurpose {
    Display,
    Automatic,
}

pub struct PreviewSnapshot {
    pub plans: Vec<ClaimablePlan>,
    pub deployed: bool,
    pub activated: Option<bool>,
    pub activation_error: Option<String>,
    pub preview_error: Option<String>,
    pub marketing_error: Option<String>,
    pub catalog_error: Option<String>,
    pub ownership_error: Option<String>,
    pub ledger_error: Option<String>,
    pub claimed: BTreeMap<String, i64>,
    pub owned: BTreeMap<String, OwnedPlan>,
    pub ineligible: BTreeMap<String, String>,
    pub claim_periods: BTreeMap<String, (Option<i64>, Option<i64>)>,
    pub daily_checkin: Value,
    account_plan_ids: BTreeSet<String>,
    catalog_plan_ids: BTreeSet<String>,
    marketing_plan_ids: BTreeSet<String>,
}

impl PreviewSnapshot {
    pub fn to_json(&self) -> Value {
        json!({
            "plans": self.plans.iter().map(|plan| self.plan_json(plan)).collect::<Vec<_>>(),
            "deployed": self.deployed,
            "activated": self.activated,
            "activationError": self.activation_error,
            "previewError": self.preview_error,
            "marketingError": self.marketing_error,
            "catalogError": self.catalog_error,
            "ownershipError": self.ownership_error,
            "ledgerError": self.ledger_error,
            "dailyCheckin": self.daily_checkin,
        })
    }

    fn plan_json(&self, plan: &ClaimablePlan) -> Value {
        let claimed_at = self.claimed.get(&plan.plan_id).copied();
        let owned = self.owned.get(&plan.plan_id).filter(|owned| owned.matches_activity(plan));
        let claimed = claimed_at.is_some() || owned.is_some();
        let account_preview = self.account_plan_ids.contains(&plan.plan_id);
        let rejection = self.ineligible.get(&plan.plan_id);
        let claim_state = if claimed { "claimed" } else if rejection.is_some() { "ineligible" }
            else if account_preview { "claimable" } else { "unknown" };
        let mut sources = Vec::new();
        if account_preview { sources.push("preview"); }
        if self.marketing_plan_ids.contains(&plan.plan_id) { sources.push("marketing"); }
        if self.catalog_plan_ids.contains(&plan.plan_id) { sources.push("catalog"); }
        if sources.is_empty() { sources.push("ledger"); }
        let mut value = json!({
            "planId": plan.plan_id,
            "name": plan.name,
            "description": plan.description,
            "priority": plan.priority,
            "startsAt": plan.starts_at,
            "endsAt": plan.ends_at,
            "claimed": claimed,
            "claimedAt": claimed_at,
            "claimState": claim_state,
            "claimMessage": rejection,
            "source": sources[0],
            "sources": sources,
            "ownedPlan": owned.map(|owned| json!({
                "planId": owned.plan_id,
                "userPlanId": owned.user_plan_id,
                "name": owned.name,
                "state": owned.state,
                "startsAt": owned.starts_at,
                "endsAt": owned.ends_at,
                "pendingUntil": owned.pending_until,
                "entitlements": owned.entitlements.iter().map(entitlement_json).collect::<Vec<_>>(),
            })),
            "entitlements": plan.entitlements.iter().map(entitlement_json).collect::<Vec<_>>(),
        });
        if let Some((starts, ends)) = self.claim_periods.get(&plan.plan_id) {
            value["claimStartsAt"] = json!(starts);
            value["claimEndsAt"] = json!(ends);
        }
        value
    }

    fn add_account_plans(&mut self, plans: Vec<ClaimablePlan>, marketing: bool) {
        for plan in &plans {
            if marketing { self.marketing_plan_ids.insert(plan.plan_id.clone()); }
            else { self.account_plan_ids.insert(plan.plan_id.clone()); }
        }
        if !plans.is_empty() { self.deployed = true; }
        merge(&mut self.plans, plans);
    }
}

fn entitlement_json(item: &super::plans::PlanEntitlement) -> Value {
    json!({
        "showName": item.show_name, "unitType": item.unit_type,
        "grantUnits": item.grant_units, "period": item.period, "effectiveAt": item.effective_at,
    })
}

pub async fn preview(
    ctx: &PluginCtx,
    region: Region,
    account: &str,
    jwt: &str,
    device_mid: Option<&str>,
    user_id: &str,
    proxy: Option<&WireProxy>,
    purpose: PreviewPurpose,
    activate_empty: bool,
) -> Result<PreviewSnapshot, GatewayError> {
    let (billing, marketing) = tokio::join!(
        preview_billing(region, jwt, device_mid, proxy),
        marketing::query(region, jwt, device_mid, proxy),
    );
    let mut snapshot = PreviewSnapshot {
        plans: Vec::new(), deployed: false, activated: None, activation_error: None,
        preview_error: None, marketing_error: None, catalog_error: None, ownership_error: None,
        ledger_error: None, claimed: BTreeMap::new(), owned: BTreeMap::new(), ineligible: BTreeMap::new(),
        claim_periods: BTreeMap::new(), daily_checkin: Value::Null,
        account_plan_ids: BTreeSet::new(), catalog_plan_ids: BTreeSet::new(), marketing_plan_ids: BTreeSet::new(),
    };
    let mut succeeded = false;
    match billing {
        Ok(plans) => {
            succeeded = true;
            snapshot.deployed = plans.is_some();
            if let Some(plans) = plans { snapshot.add_account_plans(plans, false); }
        }
        Err(error) => snapshot.preview_error = Some(error.message),
    }
    match marketing {
        Ok(plans) => {
            succeeded = true;
            snapshot.add_account_plans(plans, true);
        }
        Err(error) => snapshot.marketing_error = Some(error.message),
    }
    if activate_empty && snapshot.plans.is_empty() && snapshot.deployed && !user_id.trim().is_empty() {
        (snapshot.activated, snapshot.activation_error) = report_activation(region, user_id, device_mid, proxy).await;
        let (billing, marketing) = tokio::join!(
            preview_billing(region, jwt, device_mid, proxy),
            marketing::query(region, jwt, device_mid, proxy),
        );
        match billing {
            Ok(Some(plans)) => {
                succeeded = true;
                snapshot.add_account_plans(plans, false);
                snapshot.preview_error = None;
            }
            Ok(None) => {}
            Err(error) => snapshot.preview_error = Some(error.message),
        }
        match marketing {
            Ok(plans) => {
                succeeded = true;
                snapshot.add_account_plans(plans, true);
                snapshot.marketing_error = None;
            }
            Err(error) => snapshot.marketing_error = Some(error.message),
        }
    }
    let saved = match state::preview_state(ctx, region, account, jwt, device_mid, user_id).await {
        Ok(saved) => saved,
        Err(error) => { snapshot.ledger_error = Some(error.message); state::PreviewState::default() }
    };
    snapshot.claimed = saved.claimed;
    snapshot.owned = saved.owned;
    snapshot.ineligible = saved.ineligible;
    snapshot.claim_periods = saved.claim_periods;
    let checkin_plan_ids = snapshot.account_plan_ids.union(&snapshot.marketing_plan_ids)
        .cloned().collect::<BTreeSet<_>>();
    merge(&mut snapshot.plans, saved.checkin_plans);
    let saved_plans = saved.plans;
    if matches!(purpose, PreviewPurpose::Display) {
        match catalog::query(region, proxy).await {
            Ok(plans) => {
                succeeded = true;
                if let Some(plans) = plans {
                    if !plans.is_empty() { snapshot.deployed = true; }
                    snapshot.catalog_plan_ids.extend(plans.iter().map(|plan| plan.plan_id.clone()));
                    merge(&mut snapshot.plans, plans);
                }
            }
            Err(error) => snapshot.catalog_error = Some(error.message),
        }
        merge(&mut snapshot.plans, saved_plans.clone());
        snapshot.claimed.retain(|id, at| {
            snapshot.plans.iter().find(|plan| &plan.plan_id == id).is_none_or(|plan| {
                match (plan.starts_at, snapshot.claim_periods.get(id).and_then(|(_, end)| *end)
                    .or_else(|| saved_plans.iter().find(|saved| &saved.plan_id == id).and_then(|saved| saved.ends_at)))
                {
                    (Some(start), Some(end)) => end > start,
                    (Some(start), None) => start <= *at / 1000,
                    _ => true,
                }
            })
        });
        let needs_ownership = snapshot.plans.iter().any(|plan| {
            !snapshot.owned.get(&plan.plan_id).is_some_and(|owned| owned.matches_activity(plan))
        });
        if needs_ownership && !jwt.trim().is_empty() {
            match ownership::query(region, account, jwt, device_mid, proxy).await {
                Ok(plans) => {
                    for plan in &snapshot.plans {
                        if let Some(owned) = plans.iter().filter(|owned| owned.matches_activity(plan))
                            .max_by_key(|owned| owned.starts_at)
                        {
                            snapshot.owned.insert(plan.plan_id.clone(), owned.clone());
                        }
                    }
                }
                Err(error) => snapshot.ownership_error = Some(error.message),
            }
        }
    }
    // ── 过期套餐不进展示列表（issue #37）──────────────────────────
    // `saved.plans`（台账）是无条件并回展示列表的，于是**每一期活动结束后都会
    // 在列表里留一条**：窗口已过、`claimed` 里又因为「窗口过了就不算领过」
    // （见 `state.rs` 的 retain）而没有它 ⇒ `claim_state` 落到 `unknown` ⇒
    // 界面渲染成「待确认」+「尝试领取」，点下去会对一个已结束的活动发 claim，
    // 还要白耗一次一次性的人机验证结果。
    //
    // 判据（三种都不丢）：
    //   · 已领取（台账里有 claim 时刻）—— 历史事实，要留着；
    //   · 账号名下有这份套餐（`owned` 匹配活动）—— 那是「已领取但上游发现
    //     接口不再返回」的正常展示对象，issue 里明确要求保留；
    //   · 窗口还没结束，或上游没给结束时刻（不知道就不猜，留着）。
    // 其余（窗口已过 + 没领 + 名下没有）一定是历史残留，丢弃。
    //
    // ⚠️ 必须放在 `ownership::query` **之后**：那段才填 `snapshot.owned`，
    // 放前面会把「名下已有」的条目一起误删。
    // ⚠️ 必须放在 `remember_preview` **之前**：台账由这份列表回写，放后面
    // 等于每轮又把过期条目写回台账，下一轮照样翻出来。
    let now_secs = crate::logging::now_ms() / 1000;
    snapshot.plans.retain(|plan| {
        plan_is_current(plan, &snapshot.claimed, &snapshot.owned, now_secs)
    });
    match state::remember_preview(
        ctx, region, account, jwt, device_mid, user_id, &snapshot.plans, &snapshot.owned,
        &checkin_plan_ids, snapshot.preview_error.is_none() && snapshot.marketing_error.is_none()
            && snapshot.catalog_error.is_none() && snapshot.ownership_error.is_none()
            && snapshot.ledger_error.is_none(),
    ).await {
        Ok(daily_checkin) => snapshot.daily_checkin = daily_checkin,
        Err(error) => snapshot.ledger_error = Some(error.message),
    }
    for (source, error) in [
        ("账号预览", &snapshot.preview_error), ("营销活动", &snapshot.marketing_error),
        ("匿名目录", &snapshot.catalog_error), ("账号套餐", &snapshot.ownership_error),
        ("领取台账", &snapshot.ledger_error),
    ] {
        if let Some(error) = error { logging::log("[Claim]", &format!("ZCode {source}未完成：{error}")); }
    }
    if !succeeded && snapshot.plans.is_empty() {
        return Err(GatewayError::with_status(502, format!(
            "套餐查询失败：{}",
            [snapshot.preview_error.as_deref(), snapshot.marketing_error.as_deref(), snapshot.catalog_error.as_deref()]
                .into_iter().flatten().collect::<Vec<_>>().join("；"),
        )));
    }
    Ok(snapshot)
}

/// 一条套餐该不该出现在**展示列表**里（issue #37）。
///
/// ── 三种一律保留 ────────────────────────────────────────────
///   · **已领取**（台账里有 claim 时刻）—— 历史事实，用户要能回看；
///   · **账号名下有这份套餐**（`owned` 匹配本活动）—— 那是「已领取但上游发现
///     接口不再返回」的正常展示对象，issue 里明确要求保留；
///   · **窗口还没结束**，或**上游没给结束时刻**（不知道就不猜，留着）。
///
/// 其余（窗口已过 + 没领 + 名下没有）一定是台账残留，丢弃。
pub(super) fn plan_is_current(
    plan: &ClaimablePlan,
    claimed: &std::collections::BTreeMap<String, i64>,
    owned: &std::collections::BTreeMap<String, OwnedPlan>,
    now_secs: i64,
) -> bool {
    if claimed.contains_key(&plan.plan_id) {
        return true;
    }
    if owned.get(&plan.plan_id).is_some_and(|owned| owned.matches_activity(plan)) {
        return true;
    }
    plan.ends_at.is_none_or(|end| end > now_secs)
}

pub(crate) async fn resolve_target(
    ctx: &PluginCtx,
    region: Region,
    account: &str,
    jwt: &str,
    device_mid: Option<&str>,
    user_id: &str,
    proxy: Option<&WireProxy>,
    requested: &str,
) -> Result<Option<ClaimablePlan>, GatewayError> {
    let requested = requested.trim();
    if !requested.is_empty() {
        if super::plans::identifier(&Value::String(requested.to_string())).is_none() {
            return Err(GatewayError::with_status(400, "套餐标识无效"));
        }
        if let Some(plan) = state::known_plan(ctx, region, account, requested, jwt, device_mid, user_id).await {
            return Ok(Some(plan));
        }
    }
    let snapshot = preview(
        ctx, region, account, jwt, device_mid, user_id, proxy, PreviewPurpose::Automatic, false,
    ).await;
    if !requested.is_empty() {
        let plan = snapshot.ok().and_then(|snapshot| snapshot.plans.into_iter().find(|plan| plan.plan_id == requested));
        // 点名领取不依赖预览成功；上游 claim 才是资格的最终判据。
        return Ok(Some(plan.unwrap_or_else(|| ClaimablePlan {
            plan_id: requested.to_string(), name: requested.to_string(), description: String::new(),
            priority: 0, starts_at: None, ends_at: None, entitlements: Vec::new(),
            marketing_campaign_ids: Vec::new(),
        })));
    }
    let snapshot = snapshot?;
    Ok(snapshot.plans.into_iter().find(|plan| {
        !snapshot.claimed.contains_key(&plan.plan_id)
            && !snapshot.owned.get(&plan.plan_id).is_some_and(|owned| owned.matches_activity(plan))
    }))
}

#[cfg(test)]
mod expiry_filter_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn plan(id: &str, starts: i64, ends: i64) -> ClaimablePlan {
        ClaimablePlan {
            plan_id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            priority: 0,
            starts_at: Some(starts),
            ends_at: Some(ends),
            entitlements: Vec::new(),
            marketing_campaign_ids: Vec::new(),
        }
    }

    /// 窗口已过、没领、名下也没有 ⇒ 必须从展示列表里消失（issue #37 的主症状）。
    #[test]
    fn an_expired_unclaimed_plan_is_dropped() {
        let claimed = BTreeMap::new();
        let owned = BTreeMap::new();
        // 窗口 11/4 19:00 → 11/5 09:00，现在 11/5 19:24
        let now = 1_793_846_000_i64;
        assert!(!plan_is_current(&plan("zcode-v3-start-plan-gb-1104", 1_793_790_000, 1_793_840_400), &claimed, &owned, now));
    }

    /// 窗口已过但**已领取** ⇒ 保留（历史事实，用户要能回看）。
    #[test]
    fn an_expired_but_claimed_plan_is_kept() {
        let mut claimed = BTreeMap::new();
        claimed.insert("plan-a".to_string(), 1_793_800_000_i64);
        let owned = BTreeMap::new();
        let now = 1_793_846_000_i64;
        assert!(plan_is_current(&plan("plan-a", 1_793_790_000, 1_793_840_400), &claimed, &owned, now));
    }

    /// 窗口已过，但账号**名下有一个更新的同 id 实例**（后面某一期又领到了）
    /// ⇒ 保留。`matches_activity` 的判据是「实例结束时刻晚于活动开始时刻」，
    /// 所以这里的 `ends_at` 必须是将来时间 —— 它代表的是「名下的那份还有效」。
    #[test]
    fn an_expired_plan_owned_by_the_account_is_kept() {
        let claimed = BTreeMap::new();
        let candidate = plan("plan-b", 1_793_790_000, 1_793_840_400);
        let mut owned = BTreeMap::new();
        owned.insert(
            "plan-b".to_string(),
            OwnedPlan {
                plan_id: "plan-b".to_string(),
                user_plan_id: None,
                name: "plan-b".to_string(),
                state: "active".to_string(),
                starts_at: Some(1_793_843_200),
                // 将来的结束时刻：`matches_activity` 会先排除「已过期的名下实例」
                ends_at: Some(crate::http::now_ms() / 1000 + 86_400),
                pending_until: None,
                entitlements: Vec::new(),
            },
        );
        let now = 1_793_846_000_i64;
        assert!(plan_is_current(&candidate, &claimed, &owned, now));
    }

    /// 窗口还没结束 ⇒ 一律保留（本轮可领的那一条不能被误删）。
    #[test]
    fn a_current_plan_is_kept() {
        let claimed = BTreeMap::new();
        let owned = BTreeMap::new();
        let now = 1_793_846_000_i64;
        assert!(plan_is_current(&plan("plan-c", 1_793_843_200, 1_793_893_200), &claimed, &owned, now));
    }

    /// 上游没给结束时刻 ⇒ 不猜，保留（`ends_at` 缺失不等于过期）。
    #[test]
    fn a_plan_without_an_end_time_is_kept() {
        let claimed = BTreeMap::new();
        let owned = BTreeMap::new();
        let mut open_ended = plan("plan-d", 1_793_790_000, 0);
        open_ended.ends_at = None;
        assert!(plan_is_current(&open_ended, &claimed, &owned, 1_793_846_000_i64));
    }
}
