//! # 发现目录 —— 大规模产出治理层
//!
//! openai/math 管道（~4000 题 → 721 手稿 → 373 族，42% 形式化验证，修正记录
//! 为新版本且旧版永不删除）的四件套，逐项落到裁决账本上：
//!
//! 1. **族折叠**：大量发现按**根因签名**折叠成族（721 → 373 的同类项折叠）。
//!    折叠靠结构规范化（剥尾部实例限定组、折叠大小写与空白），不是靠词表——
//!    概念级"换词不换设计"的同构检测归 [`crate::vocab`]，发现级根因归这里。
//! 2. **验证层级**：每条发现按**证据形态**机械分级（`Tier`）——
//!    [`Tier::Reproduced`]（携带利用证据回链，可机器重放——"Lean 形态"）、
//!    [`Tier::Adjudicated`]（当前 `+1`：**扫描器永不 `+1`**，故 `+1` 必经检查/
//!    人工落锤，机械成立的权威结论）、[`Tier::Claimed`]（纯声称，"可能有错"）。
//!    **层级只看证据形态，不看身份**——人工的无证据 `-1` 与扫描器声称同层，
//!    这不是贬低人工，是把"unformalized could have issues"如实落账。
//! 3. **修正不删除**：`-1` 后 `+1` = 修复（`Fixed`）；`+1` 后 `-1` = 声明被
//!    证伪（`Refuted`）；双向反复 = 交给人（`Contradicted`）。旧裁决保留在
//!    追加式账本里，目录只给指针——"corrections recorded as new versions,
//!    previously released versions remain accessible" 的账本形态。
//! 4. **出处只看证据**：层级从账本 `history` 派生，不靠节点自述标签；
//!    目录是账本的纯函数视图，**零新增账本格式**，重放一致。
//!
//! 度量只许单向改善：`verified_ratio`（已验证比例，42% 的对应物）随
//! "声称 → 复现/检查"升级严格上升，与 [`crate::dag::Convergence`] 同纪律。
//!
//! ```
//! use trit_immune::{catalog, ImmuneDag, NodeId, NodeKind, Trit};
//! use trit_immune::verdict::{AttackVector, ExploitEvidence};
//!
//! let mut dag = ImmuneDag::root("main");
//! let a = dag.spawn(NodeId(0), NodeKind::Delta, "sql 注入（login 第 3 处）");
//! let b = dag.spawn(NodeId(0), NodeKind::AttackVector, "SQL 注入 (admin)");
//! let c = dag.spawn(NodeId(0), NodeKind::Delta, "命令注入");
//! // 红队对 a 复现成功：利用证据回链
//! dag.record(a, Trit::Vulnerable, Some(ExploitEvidence {
//!     target: a,
//!     vector: AttackVector::SqlInjection,
//!     round: 1,
//!     payload: "' OR 1=1 --".into(),
//! }), "复现");
//! dag.record(b, Trit::Unknown, None, "扫描器声称");
//! dag.record(c, Trit::Hardened, None, "回归测试通过");
//!
//! let cat = catalog(&dag);
//! // "sql 注入（login 第 3 处）" 与 "SQL 注入 (admin)" 折叠成同一族
//! assert_eq!(cat.stats.families, 2);
//! assert_eq!(cat.stats.findings, 3);
//! assert_eq!(cat.stats.reproduced, 1, "证据回链 = 已复现");
//! assert_eq!(cat.stats.adjudicated, 1, "+1 必经检查/人工");
//! assert_eq!(cat.stats.claimed, 1, "扫描器声称 = 未验证");
//! ```

use crate::dag::{ImmuneDag, NodeId, NodeKind};
use crate::trit::Trit;
use std::collections::BTreeMap;

/// 验证层级：只看**证据形态**，不看身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// 纯声称（无证据回链、无权威 `+1`）——"could have issues" 的如实落点。
    Claimed,
    /// 已裁定：当前 `+1`。扫描器永不 `+1` ⇒ `+1` 必经检查/人工落锤。
    Adjudicated,
    /// 已复现：历史携带利用证据回链的 `-1`（可机器重放的最强形态）。
    Reproduced,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Adjudicated => "adjudicated",
            Self::Reproduced => "reproduced",
        }
    }
}

/// 目录条目：一条发现的手稿卡（原题保留——折叠只作用于族键，不抹原文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub node: NodeId,
    pub kind: NodeKind,
    pub title: String,
    /// 当前账面裁决（K3 折叠后；修复/证伪以 [`Catalog::corrections`] 注记）。
    pub verdict: Trit,
    pub tier: Tier,
    pub quarantined: bool,
}

/// 族：同一根因签名的发现集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family {
    /// 根因签名（结构规范化结果；同族内所有成员共享）。
    pub signature: String,
    /// 成员按节点号升序（账本顺序，确定性）。
    pub members: Vec<CatalogEntry>,
    /// 族级裁决 = 成员最坏者胜（K3 AND 语义：一个打穿，整族存疑）。
    pub verdict: Trit,
    /// 代表成员：最坏者；并列取最小节点号。
    pub representative: NodeId,
}

/// 修正方向（账本历史派生；旧裁决永不删除）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectionKind {
    /// 先 `-1` 后 `+1`：已修复。
    Fixed,
    /// 先 `+1` 后 `-1`：声明的 `+1` 被证伪。
    Refuted,
    /// 双向都发生过：反复修正，交给人。
    Contradicted,
}

impl CorrectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::Refuted => "refuted",
            Self::Contradicted => "contradicted",
        }
    }
}

/// 一条修正注记（指针——细节在账本 `history` 里，目录不复制裁决）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correction {
    pub node: NodeId,
    pub kind: CorrectionKind,
}

/// 目录统计（42% 形式化比例的对应物）。
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogStats {
    pub findings: usize,
    pub families: usize,
    pub reproduced: usize,
    pub adjudicated: usize,
    pub claimed: usize,
    /// 矛盾节点数（[`ImmuneDag::contradictions`] 直读，修正待定的人审候选）。
    pub contradictions: usize,
    /// (reproduced + adjudicated) / findings；空目录视为 1.0（无未验证项）。
    pub verified_ratio: f64,
}

/// 发现目录：账本的纯函数视图。
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    /// 手稿清单，按节点号升序。
    pub entries: Vec<CatalogEntry>,
    /// 族，按签名字典序（确定性）。
    pub families: Vec<Family>,
    /// 修正注记，按节点号升序。
    pub corrections: Vec<Correction>,
    pub stats: CatalogStats,
}

/// 发现在账 = 非 root 且有历史事件的节点（纯 spawn 的工作项不是发现）。
fn is_finding(dag: &ImmuneDag, id: NodeId) -> bool {
    let n = dag.node(id);
    n.parent.is_some() && !n.history.is_empty()
}

fn tier_of(dag: &ImmuneDag, id: NodeId) -> Tier {
    let n = dag.node(id);
    if n.history
        .iter()
        .any(|e| e.verdict == Trit::Vulnerable && e.evidence.is_some())
    {
        Tier::Reproduced
    } else if n.verdict == Trit::Hardened || n.history.iter().any(|e| e.verdict == Trit::Hardened) {
        Tier::Adjudicated
    } else {
        Tier::Claimed
    }
}

fn correction_of(dag: &ImmuneDag, id: NodeId) -> Option<CorrectionKind> {
    let n = dag.node(id);
    // 单次扫历史：bad→后续 good = 修复；good→后续 bad = 声明被证伪；
    // 两个方向都发生 = 反复修正，交给人。`0`（Unknown）事件不改方向。
    let mut seen_bad = false;
    let mut seen_good = false;
    let mut fixed = false;
    let mut refuted = false;
    for e in &n.history {
        match e.verdict {
            Trit::Vulnerable => {
                if seen_good {
                    refuted = true;
                }
                seen_good = false;
                seen_bad = true;
            }
            Trit::Hardened => {
                if seen_bad {
                    fixed = true;
                }
                seen_bad = false;
                seen_good = true;
            }
            Trit::Unknown => {}
        }
    }
    if fixed && refuted {
        Some(CorrectionKind::Contradicted)
    } else if fixed {
        Some(CorrectionKind::Fixed)
    } else if refuted {
        Some(CorrectionKind::Refuted)
    } else {
        None
    }
}

/// 根因签名：结构规范化——折叠大小写与空白、剥尾部实例限定组
/// （`(...)` `（…）` `[...]` `【…】`，从右往左剥到剥不动）。剥完为空则回退
/// 原题 `trim`——**不静默丢**。折叠只作用于族键，原题原样保留在条目里。
pub fn signature(title: &str) -> String {
    let mut cur = collapse_ws(title);
    loop {
        let trimmed = cur.trim_end();
        let Some(close) = trimmed.chars().last() else {
            break;
        };
        let open = match close {
            ')' => '(',
            ']' => '[',
            '）' => '（',
            '】' => '【',
            _ => break,
        };
        let Some(start) = find_matching_open(trimmed, open) else {
            break;
        };
        cur = collapse_ws(&trimmed[..start]);
    }
    let canon = cur.trim();
    if canon.is_empty() {
        title.trim().to_string()
    } else {
        canon.to_string()
    }
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            pending_ws = !out.is_empty();
        } else {
            if pending_ws {
                out.push(' ');
                pending_ws = false;
            }
            for lc in c.to_lowercase() {
                out.push(lc);
            }
        }
    }
    out
}

/// 从尾部闭合符向左找「以字符串结尾的最外层组」的起始下标：右向扫描配平，
/// 开括号使深度归零的位置即组首；不配平（如未闭合括号）返回 None。
fn find_matching_open(s: &str, open: char) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices().rev() {
        if is_closer(c, open) {
            depth += 1;
        } else if c == open {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
            if depth < 0 {
                return None;
            }
        }
    }
    None
}

fn is_closer(c: char, open: char) -> bool {
    matches!(
        (c, open),
        (')', '(') | (']', '[') | ('）', '（') | ('】', '【')
    )
}

/// 构建目录（确定性：同账本重放任意次结果逐字段相等）。
pub fn catalog(dag: &ImmuneDag) -> Catalog {
    let mut entries = Vec::new();
    for n in dag.nodes() {
        let id = n.id;
        if !is_finding(dag, id) {
            continue;
        }
        entries.push(CatalogEntry {
            node: id,
            kind: n.kind,
            title: n.title.clone(),
            verdict: n.verdict,
            tier: tier_of(dag, id),
            quarantined: n.quarantined,
        });
    }

    // 族折叠：BTreeMap 键 = 签名 → 成员按节点号升序插入。
    let mut grouped: BTreeMap<String, Vec<CatalogEntry>> = BTreeMap::new();
    for e in &entries {
        grouped
            .entry(signature(&e.title))
            .or_default()
            .push(e.clone());
    }
    let families: Vec<Family> = grouped
        .into_iter()
        .map(|(sig, members)| {
            let worst = members
                .iter()
                .min_by_key(|m| (m.verdict, m.node))
                .cloned()
                .expect("族至少一个成员");
            Family {
                verdict: worst.verdict,
                representative: worst.node,
                signature: sig,
                members,
            }
        })
        .collect();

    let corrections: Vec<Correction> = entries
        .iter()
        .filter_map(|e| {
            correction_of(dag, e.node).map(|k| Correction {
                node: e.node,
                kind: k,
            })
        })
        .collect();

    let reproduced = entries
        .iter()
        .filter(|e| e.tier == Tier::Reproduced)
        .count();
    let adjudicated = entries
        .iter()
        .filter(|e| e.tier == Tier::Adjudicated)
        .count();
    let claimed = entries.iter().filter(|e| e.tier == Tier::Claimed).count();
    let findings = entries.len();
    let verified = reproduced + adjudicated;
    let stats = CatalogStats {
        findings,
        families: families.len(),
        reproduced,
        adjudicated,
        claimed,
        contradictions: dag.contradictions().len(),
        verified_ratio: if findings == 0 {
            1.0
        } else {
            verified as f64 / findings as f64
        },
    };

    Catalog {
        entries,
        families,
        corrections,
        stats,
    }
}

/// 手稿清单 TSV 导出（与 [`crate::journal::export_dag_tsv`] 同约定：
/// `#` 注释头、制表符分字段、标题内控制符折叠成空格）。结构：
/// 统计行、族行（按签名序）、条目行（按节点号序）、修正段（指针型注记）。
pub fn export_map_tsv(cat: &Catalog) -> String {
    let st = &cat.stats;
    let mut s = String::from("# trit-immune catalog map v1\n");
    s.push_str(
        "# findings\tfamilies\treproduced\tadjudicated\tclaimed\tcontradictions\tverified_ratio\n",
    );
    s.push_str(&format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{:.4}\n",
        st.findings,
        st.families,
        st.reproduced,
        st.adjudicated,
        st.claimed,
        st.contradictions,
        st.verified_ratio
    ));
    s.push_str("# family\tsignature\tverdict\tmembers\trepresentative\n");
    for f in &cat.families {
        s.push_str(&format!(
            "FAM\t{}\t{}\t{}\t{}\n",
            flat(&f.signature),
            verdict_str(f.verdict),
            f.members.len(),
            f.representative.0
        ));
    }
    s.push_str("# entry\tid\tkind\ttier\tverdict\tquarantined\ttitle\n");
    for e in &cat.entries {
        s.push_str(&format!(
            "NODE\t{}\t{}\t{}\t{}\t{}\t{}\n",
            e.node.0,
            kind_str(e.kind),
            e.tier.as_str(),
            verdict_str(e.verdict),
            e.quarantined,
            flat(&e.title)
        ));
    }
    // 修正段：指针型注记——细节在账本 history 里，旧裁决永不删除
    s.push_str("# correction\tnode\tkind\n");
    for c in &cat.corrections {
        s.push_str(&format!("CORR\t{}\t{}\n", c.node.0, c.kind.as_str()));
    }
    s
}

fn verdict_str(v: Trit) -> &'static str {
    match v {
        Trit::Vulnerable => "-1",
        Trit::Unknown => "0",
        Trit::Hardened => "+1",
    }
}

fn kind_str(k: NodeKind) -> &'static str {
    match k {
        NodeKind::Delta => "delta",
        NodeKind::AttackVector => "attack",
        NodeKind::Patch => "patch",
        NodeKind::Message => "message",
    }
}

/// 标题内控制符折叠成空格（TSV 单行纪律，与 export_dag_tsv 一致）。
fn flat(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

/// 节点历史里最近一条利用证据。
fn latest_evidence(dag: &ImmuneDag, node: NodeId) -> Option<&crate::verdict::ExploitEvidence> {
    dag.node(node)
        .history
        .iter()
        .rev()
        .find_map(|e| e.evidence.as_ref())
}

/// **族折叠的任务源**：把同类项折叠应用到劳动本身——同根因的 N 条发现
/// 不是 N 个任务，而是一个族一个任务（openai/math 的 373 族是给人看的
/// 目录，这里是给智能体排活的目录；队列长度由当前状态决定，不由工作量
/// 决定，与 [`crate::scheduler::drain_plan`] 同一条"有界劳动"纪律）。
///
/// 规则（确定性）：
/// 1. **隔离成员保节点级**——`human_review` 只能精确落在隔离节点上
///    （解除其子树），折叠会丢失落点；节点号序排在前（整链冻结最急）。
/// 2. **族级任务**——在**未隔离**成员里取最坏裁决者做代表，并列时
///    **优先带证据的成员**（红队有 PoC 可对打，修它才能复验），再取小号：
///    - 族含 `-1` → 一个 [`Task::Fix`]（证据 = 代表最近一条证据的向量）；
///    - 族全为声称（`0`，无 `+1`）→ 一个 [`Task::Review`]；
///    - 族全 `+1` → 无任务（已经收敛，劳动只花在坏消息上）。
///
/// 每轮 drain 的族级 Review/Fix 解决一个成员（替身处理器逐个落锤），
/// 固定点 = 全 `+1`；反复 drain 收敛，劳动有界。
pub fn family_tasks(cat: &Catalog, dag: &ImmuneDag) -> Vec<crate::scheduler::Task> {
    use crate::scheduler::Task;
    let mut tasks = Vec::new();
    for e in &cat.entries {
        if e.quarantined {
            tasks.push(Task::Review {
                node: e.node,
                title: e.title.clone(),
            });
        }
    }
    for f in &cat.families {
        let candidates: Vec<&CatalogEntry> = f.members.iter().filter(|m| !m.quarantined).collect();
        let Some(worst) = candidates.iter().map(|m| m.verdict).min() else {
            continue;
        };
        // 代表：最坏未隔离成员；并列优先带证据（有 PoC 可对打），再取小号
        let Some(rep) = candidates
            .iter()
            .filter(|m| m.verdict == worst)
            .min_by_key(|m| (!latest_evidence(dag, m.node).is_some(), m.node))
            .cloned()
        else {
            continue;
        };
        match worst {
            Trit::Vulnerable => tasks.push(Task::Fix {
                node: rep.node,
                evidence: latest_evidence(dag, rep.node).map(|e| format!("{}", e.vector)),
            }),
            Trit::Unknown => tasks.push(Task::Review {
                node: rep.node,
                title: rep.title.clone(),
            }),
            Trit::Hardened => {}
        }
    }
    tasks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{AttackVector, ExploitEvidence};

    fn evidence(target: NodeId) -> Option<ExploitEvidence> {
        Some(ExploitEvidence {
            target,
            vector: AttackVector::SqlInjection,
            round: 1,
            payload: "poc".into(),
        })
    }

    #[test]
    fn empty_catalog_all_zeros_ratio_one() {
        let dag = ImmuneDag::root("main");
        let cat = catalog(&dag);
        assert_eq!(cat.stats.findings, 0);
        assert_eq!(cat.stats.families, 0);
        assert_eq!(cat.corrections, Vec::new());
        assert!(
            (cat.stats.verified_ratio - 1.0).abs() < f64::EPSILON,
            "空目录视为 1.0：无未验证项，不是 0.0"
        );
    }

    #[test]
    fn pure_spawns_are_not_findings() {
        let mut dag = ImmuneDag::root("main");
        dag.spawn(NodeId(0), NodeKind::Delta, "开发增量未测");
        let cat = catalog(&dag);
        assert_eq!(cat.stats.findings, 0, "空历史 = 工作项，不进发现目录");
    }

    #[test]
    fn family_folds_same_signature_and_splits_different() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "sql 注入（login 第 3 处）");
        let b = dag.spawn(NodeId(0), NodeKind::AttackVector, "SQL 注入 (admin)");
        let c = dag.spawn(NodeId(0), NodeKind::Delta, "命令注入");
        dag.record(a, Trit::Unknown, None, "声称");
        dag.record(b, Trit::Unknown, None, "声称");
        dag.record(c, Trit::Unknown, None, "声称");
        let cat = catalog(&dag);
        assert_eq!(cat.stats.findings, 3, "三条发现全在账");
        assert_eq!(cat.stats.families, 2, "同根因折叠成族");
        let fam = &cat.families[0];
        assert_eq!(fam.signature, "sql 注入", "签名剥实例限定组并折叠大小写");
        assert_eq!(fam.members.len(), 2);
        assert_eq!(fam.verdict, Trit::Unknown);
        assert_eq!(fam.representative, a, "并列最坏取最小节点号");
    }

    #[test]
    fn family_verdict_is_worst_member() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "同一根因");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "同一根因 (b)");
        dag.record(a, Trit::Unknown, None, "声称");
        dag.record(b, Trit::Vulnerable, None, "打穿");
        let cat = catalog(&dag);
        let fam = &cat.families[0];
        assert_eq!(fam.verdict, Trit::Vulnerable, "族级 K3 AND：最坏者胜");
        assert_eq!(fam.representative, b, "代表 = 最坏成员");
    }

    #[test]
    fn tier_rules_are_evidence_only() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "发现 A");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "发现 B");
        let c = dag.spawn(NodeId(0), NodeKind::Delta, "发现 C");
        let d = dag.spawn(NodeId(0), NodeKind::Delta, "发现 D");
        dag.record(a, Trit::Vulnerable, evidence(a), "复现");
        dag.record(b, Trit::Hardened, None, "检查通过");
        dag.record(c, Trit::Vulnerable, None, "人工判坏无证据");
        dag.record(d, Trit::Unknown, None, "扫描器声称");
        let cat = catalog(&dag);
        let tier = |id: NodeId| cat.entries.iter().find(|e| e.node == id).unwrap().tier;
        assert_eq!(tier(a), Tier::Reproduced, "证据回链 = 已复现");
        assert_eq!(
            tier(b),
            Tier::Adjudicated,
            "+1 必经检查/人工（扫描器永不 +1）"
        );
        assert_eq!(
            tier(c),
            Tier::Claimed,
            "人工无证据 -1 与扫描器声称同层：层级只看证据形态"
        );
        assert_eq!(tier(d), Tier::Claimed, "0 声称未验证");
    }

    #[test]
    fn reproduced_tier_survives_fix() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "发现");
        dag.record(a, Trit::Vulnerable, evidence(a), "复现");
        dag.record(a, Trit::Hardened, None, "修复通过");
        let cat = catalog(&dag);
        let e = cat.entries.iter().find(|e| e.node == a).unwrap();
        assert_eq!(e.verdict, Trit::Hardened, "账面 = 最新裁决");
        assert_eq!(
            e.tier,
            Tier::Reproduced,
            "复现历史不因修复消失——机器可查的证据是事实"
        );
    }

    #[test]
    fn corrections_fixed_refuted_contradicted() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "修复");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "证伪");
        let c = dag.spawn(NodeId(0), NodeKind::Delta, "反复");
        let d = dag.spawn(NodeId(0), NodeKind::Delta, "无修正");
        dag.record(a, Trit::Vulnerable, None, "判坏");
        dag.record(a, Trit::Hardened, None, "修好");
        dag.record(b, Trit::Hardened, None, "曾判好");
        dag.record(b, Trit::Vulnerable, None, "后被打穿");
        dag.record(c, Trit::Vulnerable, None, "坏");
        dag.record(c, Trit::Hardened, None, "好");
        dag.record(c, Trit::Vulnerable, None, "又坏");
        dag.record(d, Trit::Unknown, None, "纯声称");
        let cat = catalog(&dag);
        let kind = |id: NodeId| {
            cat.corrections
                .iter()
                .find(|x| x.node == id)
                .map(|x| x.kind)
        };
        assert_eq!(kind(a), Some(CorrectionKind::Fixed));
        assert_eq!(
            kind(b),
            Some(CorrectionKind::Refuted),
            "声明的 +1 被打穿 = 证伪"
        );
        assert_eq!(
            kind(c),
            Some(CorrectionKind::Contradicted),
            "双向反复交给人"
        );
        assert_eq!(kind(d), None);
        // 修正不删除：目录是纯视图，账本 history 原样保留
        assert_eq!(dag.node(a).history.len(), 2);
        assert_eq!(dag.node(c).history.len(), 3);
    }

    #[test]
    fn quarantine_event_does_not_fabricate_corrections() {
        let mut dag = ImmuneDag::root("main");
        let m = dag.spawn(NodeId(0), NodeKind::Message, "可疑消息");
        dag.quarantine(m, "污染");
        let cat = catalog(&dag);
        assert!(
            cat.corrections.is_empty(),
            "隔离事件带当前裁决（0）入历史，不得伪造修正方向"
        );
        assert_eq!(cat.entries[0].tier, Tier::Claimed);
        assert!(cat.entries[0].quarantined);
    }

    #[test]
    fn signature_canonicalizes_and_never_drops() {
        assert_eq!(signature("SQL 注入"), signature("sql 注入"), "大小写折叠");
        assert_eq!(signature("sql 注入"), signature(" sql  注入 "), "空白折叠");
        assert_eq!(
            signature("sql 注入 (app.rs:12)"),
            signature("SQL 注入"),
            "尾部实例组剥离"
        );
        assert_eq!(
            signature("越权（第 3 处）"),
            signature("越权"),
            "全角括号剥离"
        );
        assert_eq!(signature("嵌套 [组 (内)]"), signature("嵌套"), "嵌套组剥离");
        assert_eq!(signature("(only)"), "(only)", "剥完为空回退原题——不静默丢");
        assert_eq!(signature(""), "", "空题如实空（空签名各族自聚）");
        assert_eq!(signature("未闭合 (括号"), "未闭合 (括号", "未闭合组不剥离");
    }

    #[test]
    fn catalog_replay_consistency() {
        use crate::delta::{encode, Delta};
        use crate::hlc::Clock;

        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "发现 (1)");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "发现 (2)");
        dag.record(a, Trit::Vulnerable, evidence(a), "复现");
        dag.record(b, Trit::Unknown, None, "声称");
        dag.quarantine(b, "来源可疑");
        dag.human_review(a, Trit::Hardened, "修复");

        // 实时构建
        let live = catalog(&dag);
        // 全量重放构建：日志行 = `<ts>\t<delta>`（与 Journal 落盘同格式）
        let mut clock = Clock::with_now(9, Box::new(|| 0u64));
        let deltas: Vec<Delta> = vec![
            Delta::Root {
                title: "main".into(),
            },
            Delta::Spawn {
                parent: NodeId(0),
                kind: NodeKind::Delta,
                title: "发现 (1)".into(),
            },
            Delta::Spawn {
                parent: NodeId(0),
                kind: NodeKind::Delta,
                title: "发现 (2)".into(),
            },
            Delta::Record {
                id: a,
                verdict: Trit::Vulnerable,
                evidence: evidence(a),
                note: "复现".into(),
            },
            Delta::Record {
                id: b,
                verdict: Trit::Unknown,
                evidence: None,
                note: "声称".into(),
            },
            Delta::Quarantine {
                id: b,
                note: "来源可疑".into(),
            },
            Delta::HumanReview {
                id: a,
                verdict: Trit::Hardened,
                note: "修复".into(),
            },
        ];
        let lines: Vec<String> = deltas
            .iter()
            .map(|d| format!("{}\t{}", clock.tick(), encode(d)))
            .collect();
        let mut replayed = ImmuneDag::empty();
        for raw in &lines {
            let (_, delta) = crate::journal::parse_stamped_line(raw).expect("合法日志行");
            replayed.apply(&delta).expect("重放成功");
        }
        let replay_cat = catalog(&replayed);
        assert_eq!(
            live, replay_cat,
            "目录是账本的确定性函数：实时与重放逐字段一致"
        );
    }

    #[test]
    fn verified_ratio_monotone_on_upgrade() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "发现 A");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "发现 B");
        dag.record(a, Trit::Unknown, None, "声称");
        dag.record(b, Trit::Unknown, None, "声称");
        let before = catalog(&dag).stats.verified_ratio;
        assert!((before - 0.0).abs() < f64::EPSILON, "全声称 = 0 已验证");
        // 声称 → 复现（补证据）：只许升
        dag.record(a, Trit::Vulnerable, evidence(a), "补上复现");
        let after = catalog(&dag).stats.verified_ratio;
        assert!(
            after > before,
            "声称升级为复现，verified_ratio 严格上升（单向改善）"
        );
        assert!((after - 0.5).abs() < 1e-9);
    }

    #[test]
    fn map_tsv_shape_and_flat_titles() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "带\t制表符的题 (1)");
        dag.record(a, Trit::Unknown, None, "声称");
        let cat = catalog(&dag);
        let tsv = export_map_tsv(&cat);
        let lines: Vec<&str> = tsv.lines().collect();
        // 行序：版本注释 + 统计注释 + 统计值 + 族注释 + 族行 + 条目注释 + 条目行
        assert!(lines[0].starts_with("# trit-immune catalog map v1"));
        assert_eq!(lines[2].split('\t').count(), 7, "统计行恒 7 列");
        assert!(lines[4].starts_with("FAM\t"), "族行前缀");
        let node_line = lines[6];
        assert!(node_line.starts_with("NODE\t"), "条目行前缀");
        assert_eq!(node_line.split('\t').count(), 7, "条目行恒 7 列");
        assert!(
            node_line.contains("带 制表符的题"),
            "标题内控制符折叠成空格，列数不破"
        );
        // 修正段恒在尾部（无修正 = 注释行收尾，段不缺席）
        assert_eq!(lines[7], "# correction\tnode\tkind");
        assert_eq!(lines.len(), 8);
    }

    #[test]
    fn map_tsv_includes_corrections() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "发现");
        dag.record(a, Trit::Vulnerable, None, "判坏");
        dag.record(a, Trit::Hardened, None, "修好");
        let cat = catalog(&dag);
        let tsv = export_map_tsv(&cat);
        let corr: Vec<&str> = tsv.lines().filter(|l| l.starts_with("CORR\t")).collect();
        assert_eq!(
            corr,
            vec!["CORR\t1\tfixed"],
            "修正段逐行输出方向；旧裁决仍在账本历史不删"
        );
        assert_eq!(dag.node(a).history.len(), 2, "导出不动账本");
    }

    #[test]
    fn family_tasks_fold_to_one_task_per_family() {
        use crate::scheduler::Task;
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "sql 注入 (a)");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "SQL 注入 (b)");
        let c = dag.spawn(NodeId(0), NodeKind::Delta, "sql 注入 (c)");
        let d = dag.spawn(NodeId(0), NodeKind::Delta, "命令注入");
        let e = dag.spawn(NodeId(0), NodeKind::Delta, "命令注入 (d)");
        dag.record(a, Trit::Vulnerable, None, "打穿");
        dag.record(b, Trit::Unknown, None, "声称");
        dag.record(c, Trit::Unknown, None, "声称");
        dag.record(d, Trit::Unknown, None, "声称");
        dag.record(e, Trit::Unknown, None, "声称");
        let cat = catalog(&dag);
        let tasks = family_tasks(&cat, &dag);
        assert_eq!(tasks.len(), 2, "5 发现折成 2 族任务：{tasks:?}");
        match &tasks[0] {
            Task::Fix { node, evidence } => {
                assert_eq!(*node, a, "Fix 落在族内最坏成员（唯一 -1）");
                assert!(evidence.is_none(), "无证据回链 → evidence 空");
            }
            other => panic!("第一个任务是 Fix，得到 {other:?}"),
        }
        match &tasks[1] {
            Task::Review { node, .. } => {
                assert_eq!(*node, d, "全声称族 → 一个 Review，代表取小号");
            }
            other => panic!("第二个任务是 Review，得到 {other:?}"),
        }
        // 对照：节点级 drain_plan 是 5 个任务——折叠收益就在这一行
        assert_eq!(crate::scheduler::drain_plan(&dag, 16).len(), 5);
    }

    #[test]
    fn family_tasks_representative_prefers_evidence() {
        use crate::scheduler::Task;
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "同根因 (a)");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "同根因 (b)");
        dag.record(a, Trit::Vulnerable, None, "打穿无证据");
        dag.record(b, Trit::Vulnerable, evidence(b), "复现回链");
        let cat = catalog(&dag);
        let tasks = family_tasks(&cat, &dag);
        match &tasks[..] {
            [Task::Fix { node, evidence }] => {
                assert_eq!(*node, b, "并列最坏时 Fix 落在带证据成员——修它才能复验");
                assert_eq!(evidence.as_deref(), Some("SQL注入"));
            }
            other => panic!("应为单个 Fix，得到 {other:?}"),
        }
    }

    #[test]
    fn family_tasks_quarantined_stay_node_level() {
        use crate::scheduler::Task;
        let mut dag = ImmuneDag::root("main");
        let m = dag.spawn(NodeId(0), NodeKind::Message, "可疑消息");
        let x = dag.spawn(NodeId(0), NodeKind::Delta, "可疑消息 (x)");
        dag.record(x, Trit::Unknown, None, "声称");
        dag.quarantine(m, "污染");
        let cat = catalog(&dag);
        let tasks = family_tasks(&cat, &dag);
        assert_eq!(tasks.len(), 2, "隔离节点级 Review + 族级 Review：{tasks:?}");
        assert!(
            matches!(&tasks[0], Task::Review { node, .. } if *node == m),
            "隔离成员排最前且落点精确（human_review 解除其子树）"
        );
        assert!(
            matches!(&tasks[1], Task::Review { node, .. } if *node == x),
            "族内未隔离部分折叠成一个族级 Review"
        );
    }

    #[test]
    fn family_tasks_never_fix_quarantined_member() {
        use crate::scheduler::Task;
        let mut dag = ImmuneDag::root("main");
        let q = dag.spawn(NodeId(0), NodeKind::Delta, "根因");
        let z = dag.spawn(NodeId(0), NodeKind::Delta, "根因 (z)");
        dag.record(q, Trit::Vulnerable, None, "打穿");
        dag.quarantine(q, "污染");
        dag.record(z, Trit::Unknown, None, "声称");
        let cat = catalog(&dag);
        let tasks = family_tasks(&cat, &dag);
        assert!(
            tasks.iter().all(|t| matches!(t, Task::Review { .. })),
            "族里唯一 -1 已隔离：不产生 Fix（修复不越过隔离），得到 {tasks:?}"
        );
        assert_eq!(tasks.len(), 2, "隔离 Review + 未隔离声称的族级 Review");
    }

    #[test]
    fn family_tasks_hardened_family_no_task() {
        let mut dag = ImmuneDag::root("main");
        let a = dag.spawn(NodeId(0), NodeKind::Delta, "已收敛 (a)");
        let b = dag.spawn(NodeId(0), NodeKind::Delta, "已收敛 (b)");
        dag.record(a, Trit::Hardened, None, "检查通过");
        dag.record(b, Trit::Hardened, None, "检查通过");
        let cat = catalog(&dag);
        assert!(
            family_tasks(&cat, &dag).is_empty(),
            "全 +1 族无任务：劳动只花在坏消息上"
        );
    }

    #[test]
    fn scheduler_drains_family_tasks_bounded() {
        use crate::scheduler::{Handler, Scheduler, Task};
        struct Executed(usize);
        impl Handler for Executed {
            fn handle(&mut self, _task: &Task) -> Result<(), String> {
                self.0 += 1;
                Ok(())
            }
        }
        let mut dag = ImmuneDag::root("main");
        for (i, title) in ["a (1)", "a (2)", "a (3)", "b (1)", "b (2)", "b (3)"]
            .iter()
            .enumerate()
        {
            let n = dag.spawn(NodeId(0), NodeKind::Delta, title);
            dag.record(n, Trit::Vulnerable, None, "打穿");
            let _ = i;
        }
        let cat = catalog(&dag);
        let folded = family_tasks(&cat, &dag);
        assert_eq!(folded.len(), 2, "6 发现 2 族 → 2 任务");
        let mut h = Executed(0);
        let report = Scheduler::new(2).run(folded, &mut h);
        assert_eq!(
            (report.total, report.executed, report.failed),
            (2, 2, 0),
            "调度器恰好执行一次每族任务"
        );
        assert_eq!(h.0, 2);
    }
}
