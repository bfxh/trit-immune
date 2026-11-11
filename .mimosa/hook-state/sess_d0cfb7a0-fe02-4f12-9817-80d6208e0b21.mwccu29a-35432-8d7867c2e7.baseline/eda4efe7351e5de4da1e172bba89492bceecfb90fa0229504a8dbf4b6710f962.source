//! 裁决 TMR（三模冗余表决）——MEMETIC-RESISTANCE 想法三的库形态。
//!
//! 太空抗干扰的 TMR 迁移到判定层：三个**独立扫描器**对同一发现各出三值
//! 判定，多数票合成一个账本节点。单引擎被投毒（误报率抬高或被致盲）被
//! 另外两票压制——**"扫描器永不 +1"的工程化强化：单个扫描器的污染无法
//! 独立入账**。
//!
//! 语义（与太空 TMR 的差异，MEMETIC-RESISTANCE §一）：
//! - ≥2 票同值 → 该值（多数成立）；
//! - 三票各异 / 无 ≥2 多数 → `Unknown`（弃权：证据不一致 = 不裁决；
//!   矛盾细节留给 Belnap 层与人工复核——本层不裁决不隐瞒）；
//! - 已知边界：防单点投毒**不防合谋**（2/3 被同一攻击者控制即失守——
//!   合谋防御回到溯源与 B4 矛盾检测，不在表决层）。

use crate::dag::{NodeKind, NodeId};
use crate::journal::Journal;
use trit_core::value::Trit;
use std::io;

/// 三票 TMR 表决：≥2 票同值 → 该值；无 ≥2 多数（三票各异）→ `Unknown`。
///
/// 投毒压制示例：`(V, V, F)` → `V`（被投毒的 F 票被两干净票否决）；
/// `(V, U, U)` → `U`（弃权占多数——两扫描器没看见，一个看见了，
/// 证据不足以裁决）；`(V, U, F)` → `U`（三方不一致 → 弃权）。
pub fn tmr_vote(votes: [Trit; 3]) -> Trit {
    let mut counts: BTreeMap<Trit, usize> = BTreeMap::new();
    for v in votes {
        *counts.entry(v).or_default() += 1;
    }
    match counts.into_iter().max_by_key(|(_, n)| *n) {
        Some((v, n)) if n >= 2 => v,
        _ => Trit::Unknown,
    }
}

/// 三扫描器判定入账：spawn 发现节点 + TMR 表决落账（注记带三票溯源）。
///
/// 三票的判定历史**全量保留**在注记里（修正不删除：单票视角不丢弃——
/// 事后审计可以看到被压制的票说了什么）。
pub fn tmr_record(
    journal: &mut Journal,
    parent: NodeId,
    title: &str,
    votes: [Trit; 3],
    scanner_names: [&str; 3],
) -> io::Result<NodeId> {
    let verdict = tmr_vote(votes);
    let node = journal.spawn(parent, NodeKind::Message, title)?;
    let votes_note = format!(
        "TMR[{}] {}={} / {}={} / {}={}",
        scanner_names.join(","),
        scanner_names[0],
        fmt(votes[0]),
        scanner_names[1],
        fmt(votes[1]),
        scanner_names[2],
        fmt(votes[2]),
    );
    journal.record(node, verdict, None, &votes_note)?;
    Ok(node)
}

fn fmt(v: Trit) -> &'static str {
    match v {
        Trit::Vulnerable => "-1",
        Trit::Unknown => "0",
        Trit::Hardened => "+1",
    }
}

use crate::journal::Journal;

#[cfg(test)]
mod tests {
    use super::{tmr_record, tmr_vote, Journal, NodeId, Trit};
    use Trit::{Hardened, Unknown, Vulnerable};

    #[test]
    fn majority_suppresses_single_poisoned_vote() {
        // 两干净票 + 一被投毒票（F 票想洗白注入）→ 被压制
        assert_eq!(tmr_vote([Vulnerable, Vulnerable, Hardened]), Vulnerable);
        assert_eq!(tmr_vote([Vulnerable, Vulnerable, Unknown]), Vulnerable);
        // 弃权占多数：两扫描器没看见
        assert_eq!(tmr_vote([Vulnerable, Unknown, Unknown]), Unknown);
        // 三方不一致 → 弃权（矛盾细节留给 B4 层与人工）
        assert_eq!(tmr_vote([Vulnerable, Unknown, Hardened]), Unknown);
        // 全票一致
        assert_eq!(tmr_vote([Vulnerable, Vulnerable, Vulnerable]), Vulnerable);
        assert_eq!(tmr_vote([Hardened, Hardened, Hardened]), Hardened);
        assert_eq!(tmr_vote([Unknown, Unknown, Unknown]), Unknown);
        // 反向投毒：单票想冤枉——两个干净 Hardened 票压过它
        assert_eq!(tmr_vote([Hardened, Hardened, Vulnerable]), Hardened);
    }

    #[test]
    fn tmr_record_lands_majority_with_full_provenance() {
        let dir = std::env::temp_dir().join(format!("tmr-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        let path = dir.join("tmr.tritj");
        let mut j = Journal::create_as(&path, "tmr", 0).expect("建账");
        let node = tmr_record(
            &mut j,
            NodeId(0),
            "注入能力发现",
            [Trit::Vulnerable, Trit::Vulnerable, Trit::Unknown],
            ["yara", "trit-re", "vendor-av"],
        )
        .expect("合法父节点入账");
        let dag_j = Journal::open_as(&path, 0).expect("重开");
        let n = dag_j.dag().node(node);
        assert_eq!(n.verdict, Trit::Vulnerable, "两干净票压过弃权票");
        let event = n.history.last().expect("有落账事件");
        assert!(
            event.note.contains("TMR[yara,trit-re,vendor-av]"),
            "三票溯源在注记"
        );
        assert!(
            event.note.contains("yara=-1") && event.note.contains("vendor-av=0"),
            "被压制的票与弃权票都全量保留（修正不删除）"
        );
        drop(dag_j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmr_record_unknown_on_split_votes() {
        let dir = std::env::temp_dir().join(format!("tmr-split-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        let path = dir.join("tmr.tritj");
        let mut j = Journal::create_as(&path, "tmr", 0).expect("建账");
        let node = tmr_record(
            &mut j,
            NodeId(0),
            "分歧发现",
            [Trit::Vulnerable, Trit::Unknown, Trit::Hardened],
            ["a", "b", "c"],
        )
        .expect("合法父节点入账");
        let dag_j = Journal::open_as(&path, 0).expect("重开");
        assert_eq!(
            dag_j.dag().node(node).verdict,
            Trit::Unknown,
            "三方不一致 → 弃权（不裁决不隐瞒）"
        );
        drop(dag_j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
