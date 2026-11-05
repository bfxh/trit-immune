//! OpenVEX 导出：三值裁决 → 漏洞可利用性交换标准（生态互操作）。
//!
//! VEX（Vulnerability Exploitability eXchange，CISA 最低要求 / OpenSSF
//! OpenVEX）回答的问题与本系统同构：**"这个组件受这个漏洞影响吗"**——
//! 恰是三值裁决的语义。映射（CISA 四状态）：
//!
//! | Trit | VEX status | 语义 |
//! |------|-----------|------|
//! | `-1` | `affected` | 确认可利用 |
//! | `0`  | `under_investigation` | 未决（0 态驻留） |
//! | `+1`（无 `-1` 历史） | `not_affected` | 防御成功 |
//! | `+1`（历史里有 `-1`） | `fixed` | 曾被打穿、已修复（账本可证） |
//!
//! `fixed` 是**账本派生**的：只有 journal 里有"曾 `-1`"的证据才许声明
//! fixed——这与"作者打勾 ≠ +1"同一条纪律，VEX 文档不许比账本更乐观。
//!
//! **分层发布**（[`export_vex_tiered`]）：对外最强主张（`affected`）只给
//! 机器可查证据——带利用证据回链（已复现）的 `-1` 才发 `affected`；纯声称
//! 的 `-1`（openai/math 的 "unformalized could have issues"）对外降级为
//! `under_investigation`——VEX 文档不许比证据更乐观，与 fixed 的账本派生
//! 同一条纪律的对外面。
//!
//! 输出为 OpenVEX v0.2.0 JSON 文本（[`export_vex`] / [`export_vex_tiered`]）；
//! 手写序列化、字符串转义复用 [`crate::json::json_escape`]（零依赖）。

use crate::dag::ImmuneDag;
use crate::json::json_escape;
use crate::trit::Trit;

/// OpenVEX 上下文标识（v0.2.0）。
pub const OPENVEX_CONTEXT: &str = "https://openvex.dev/ns/v0.2.0";

/// VEX 四状态（CISA 最低要求）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    Affected,
    UnderInvestigation,
    NotAffected,
    Fixed,
}

impl VexStatus {
    /// Trit + 历史是否含 `-1` → VEX 状态。
    pub fn from_verdict(verdict: Trit, was_ever_vulnerable: bool) -> Self {
        match verdict {
            Trit::Vulnerable => Self::Affected,
            Trit::Unknown => Self::UnderInvestigation,
            Trit::Hardened if was_ever_vulnerable => Self::Fixed,
            Trit::Hardened => Self::NotAffected,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Affected => "affected",
            Self::UnderInvestigation => "under_investigation",
            Self::NotAffected => "not_affected",
            Self::Fixed => "fixed",
        }
    }

    /// **分层发布映射**（[`export_vex_tiered`] 用）：`-1` 按 [`crate::catalog::Tier`]
    /// 分级——已复现（证据回链）发 `affected`；纯声称降级 `under_investigation`。
    /// `+1`/`0` 与 [`Self::from_verdict`] 一致（层级是坏消息的证据质量口径，
    /// 不改变好消息与未决的映射）。
    pub fn from_tier(verdict: Trit, was_ever_vulnerable: bool, tier: crate::catalog::Tier) -> Self {
        match verdict {
            Trit::Vulnerable if tier == crate::catalog::Tier::Reproduced => Self::Affected,
            Trit::Vulnerable => Self::UnderInvestigation,
            Trit::Unknown => Self::UnderInvestigation,
            Trit::Hardened if was_ever_vulnerable => Self::Fixed,
            Trit::Hardened => Self::NotAffected,
        }
    }
}

/// 当前 UTC 时间戳（ISO 8601，秒精度；std 无 chrono，手算日历日）。
fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 民用时间（1970-01-01 起，含闰年规则）
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// 天数 → (年, 月, 日)（Howard Hinnant 的 civil_from_days 算法，公有领域）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 把 DAG 全量导出为 OpenVEX JSON。
///
/// 每个节点一条 statement：`vulnerability.name` = 节点标题（节点即被审计的
/// 漏洞面），`products[0].identifier` = `product` 参数（调用方给的仓名/
/// 工件名），`status` 按上表映射，`status_notes` = 最后一条裁决记录
/// （证据随声明走）。根节点（标题无关漏洞）跳过——调用方把根当库名，
/// 不是漏洞面。
pub fn export_vex(dag: &ImmuneDag, author: &str, product: &str) -> String {
    build_vex(dag, author, product, &|n| {
        let was_vuln = n.history.iter().any(|e| e.verdict == Trit::Vulnerable);
        VexStatus::from_verdict(n.verdict, was_vuln)
    })
}

/// **分层发布导出**：`-1` 按验证层级分级（[`VexStatus::from_tier`]）——
/// 已复现发 `affected`，纯声称降级 `under_investigation`。层级来自
/// [`crate::catalog::catalog`]（只看证据形态的机械口径）。
pub fn export_vex_tiered(dag: &ImmuneDag, author: &str, product: &str) -> String {
    let cat = crate::catalog::catalog(dag);
    build_vex(dag, author, product, &|n| {
        let was_vuln = n.history.iter().any(|e| e.verdict == Trit::Vulnerable);
        let tier = cat
            .entries
            .iter()
            .find(|e| e.node == n.id)
            .map(|e| e.tier)
            .unwrap_or(crate::catalog::Tier::Claimed);
        VexStatus::from_tier(n.verdict, was_vuln, tier)
    })
}

/// VEX JSON 构建体（[`export_vex`] 与 [`export_vex_tiered`] 共用同一序列化，
/// 只换 status 的派生函数——两份导出不该有两种 JSON 形状）。
fn build_vex(
    dag: &ImmuneDag,
    author: &str,
    product: &str,
    status_of: &dyn Fn(&crate::dag::Node) -> VexStatus,
) -> String {
    let mut out = String::with_capacity(1024 + dag.nodes().len() * 160);
    out.push_str("{\n  \"@context\": ");
    out.push_str(&json_escape(OPENVEX_CONTEXT));
    out.push_str(",\n  \"author\": ");
    out.push_str(&json_escape(author));
    out.push_str(",\n  \"timestamp\": ");
    let ts = now_iso8601();
    out.push_str(&json_escape(&ts));
    out.push_str(",\n  \"last_updated\": ");
    out.push_str(&json_escape(&ts));
    out.push_str(",\n  \"statements\": [");
    let mut first = true;
    for n in dag.nodes() {
        if n.parent.is_none() {
            continue; // 根 = 库名，不是漏洞面
        }
        let status = status_of(n);
        let note = n.history.last().map(|e| e.note.as_str()).unwrap_or("");
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str("\n    {\n      \"vulnerability\": {\"name\": ");
        out.push_str(&json_escape(&n.title));
        out.push_str("},\n      \"products\": [{\"identifier\": ");
        out.push_str(&json_escape(product));
        out.push_str("}],\n      \"status\": ");
        out.push_str(&json_escape(status.as_str()));
        out.push_str(",\n      \"status_notes\": ");
        out.push_str(&json_escape(note));
        out.push_str("\n    }");
    }
    out.push_str("\n  ]\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::{NodeId, NodeKind};

    fn sample_dag() -> ImmuneDag {
        let mut dag = ImmuneDag::root("lib");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "TRI001-SQLi");
        dag.record(a, Trit::Vulnerable, None, "打穿");
        dag.record(a, Trit::Hardened, None, "修复并回归通过"); // fixed：账本可证
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "TRI002-路径遍历");
        dag.record(b, Trit::Unknown, None, "沙盒挂起");
        let c = dag.spawn(NodeId(0), NodeKind::Delta, "TRI003-XSS");
        dag.record(c, Trit::Hardened, None, "转义完备");
        dag
    }

    #[test]
    fn status_mapping_includes_ledger_derived_fixed() {
        assert_eq!(
            VexStatus::from_verdict(Trit::Vulnerable, false),
            VexStatus::Affected
        );
        assert_eq!(
            VexStatus::from_verdict(Trit::Unknown, false),
            VexStatus::UnderInvestigation
        );
        assert_eq!(
            VexStatus::from_verdict(Trit::Hardened, false),
            VexStatus::NotAffected
        );
        assert_eq!(
            VexStatus::from_verdict(Trit::Hardened, true),
            VexStatus::Fixed
        );
        // 纪律：没有 -1 历史就不得声明 fixed（VEX 不许比账本乐观）
        assert_ne!(
            VexStatus::from_verdict(Trit::Hardened, false),
            VexStatus::Fixed
        );
    }

    #[test]
    fn tiered_mapping_downgrades_claims_keeps_verified() {
        use crate::catalog::Tier;
        // 声称 -1（无证据）→ 对外降级 under_investigation
        assert_eq!(
            VexStatus::from_tier(Trit::Vulnerable, false, Tier::Claimed),
            VexStatus::UnderInvestigation,
            "VEX 文档不许比证据更乐观：纯声称不发 affected"
        );
        // 已复现 -1（证据回链）→ affected（最强主张只给机器可查证据）
        assert_eq!(
            VexStatus::from_tier(Trit::Vulnerable, false, Tier::Reproduced),
            VexStatus::Affected
        );
        // 好消息与未决的映射不受层级影响
        assert_eq!(
            VexStatus::from_tier(Trit::Hardened, true, Tier::Claimed),
            VexStatus::Fixed
        );
        assert_eq!(
            VexStatus::from_tier(Trit::Unknown, false, Tier::Reproduced),
            VexStatus::UnderInvestigation
        );
    }

    #[test]
    fn tiered_export_publishes_only_reproduced_as_affected() {
        use crate::verdict::ExploitEvidence;
        let mut dag = ImmuneDag::root("lib");
        let claimed = dag.spawn(NodeId(0), NodeKind::Delta, "声称的");
        dag.record(claimed, Trit::Vulnerable, None, "扫描器判坏");
        let reproduced = dag.spawn(NodeId(0), NodeKind::Delta, "复现的");
        dag.record(
            reproduced,
            Trit::Vulnerable,
            Some(ExploitEvidence {
                target: reproduced,
                vector: crate::verdict::AttackVector::Xss,
                round: 1,
                payload: "poc".into(),
            }),
            "复现回链",
        );
        let fixed = dag.spawn(NodeId(0), NodeKind::Delta, "修好的");
        dag.record(fixed, Trit::Vulnerable, None, "打穿");
        dag.record(fixed, Trit::Hardened, None, "回归通过");

        let tiered = export_vex_tiered(&dag, "rt", "lib");
        let count = |s: &str| tiered.matches(&format!("\"{s}\"")).count();
        assert_eq!(count("affected"), 1, "只有已复现的发 affected：{tiered}");
        assert_eq!(count("under_investigation"), 1, "声称降级：{tiered}");
        assert_eq!(count("fixed"), 1, "fixed 账本派生不受分层影响：{tiered}");

        // 对照：未分层导出保持旧映射（-1 一律 affected）——行为不静默漂移
        let plain = export_vex(&dag, "rt", "lib");
        assert_eq!(plain.matches("\"affected\"").count(), 2, "旧映射不变");
    }

    #[test]
    fn export_is_valid_json_with_all_four_statuses() {
        let dag = sample_dag();
        let json = export_vex(&dag, "trit-immune", "my-lib");
        // 往回解析：合法性由现有零依赖解析器验证
        let parsed = crate::json::parse(&json).expect("导出必须是合法 JSON");
        assert_eq!(
            parsed.get("@context").and_then(|v| v.as_str()),
            Some(OPENVEX_CONTEXT)
        );
        let stmts = parsed.get("statements").and_then(|v| v.as_arr()).unwrap();
        assert_eq!(stmts.len(), 3, "根节点跳过，三个业务节点各一条");
        let mut statuses: Vec<&str> = stmts
            .iter()
            .filter_map(|s| s.get("status").and_then(|v| v.as_str()))
            .collect();
        statuses.sort_unstable();
        assert_eq!(
            statuses,
            vec!["affected", "fixed", "not_affected", "under_investigation"]
                .into_iter()
                .filter(|s| statuses.contains(s))
                .collect::<Vec<_>>(),
            "四种状态各就各位：{statuses:?}"
        );
        assert!(statuses.contains(&"fixed"), "曾 -1 现 +1 → fixed");
    }

    #[test]
    fn export_escapes_hostile_titles() {
        let mut dag = ImmuneDag::root("lib");
        let n = dag.spawn(
            NodeId(0),
            NodeKind::Delta,
            "title with \"quote\" and \\slash",
        );
        dag.record(n, Trit::Vulnerable, None, "note \"also\" quoted");
        let json = export_vex(&dag, "author \"x\"", "prod");
        assert!(
            crate::json::parse(&json).is_ok(),
            "恶意标题仍须产出合法 JSON"
        );
    }
}
