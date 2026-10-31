//! 跨仓 Delta 完整协议测试：`Fleet::sync_cross_repo`。
//!
//! 语义纪律（每条一个用例）：
//! 1. 坏消息落账并持久化（目标仓独立重开仍可见，门禁收紧）；
//! 2. `+1` 永不跨仓落账（下游的 +1 必须自己挣）；已证拦截边不落坏消息；
//! 3. 幂等：反复跑反熵，第二次起零落账；
//! 4. 不覆盖：目标已更坏时跳过（单调，不洗白）；
//! 5. 落账与查询无矛盾：落账后 `effective_verdicts` 与账目一致；
//! 6. 未知仓/越界节点如实跳过不炸。

use trit_immune::*;
use trit_immune::fleet::CrossRepoDelta;

fn tmp(tag: &str, n: u64) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("trit-cross-{tag}-{}-{n}.journal", std::process::id()))
}

/// 建一个最小仓：根 + 一个业务节点（指定裁决），落盘关闭。
fn make_repo(path: &std::path::Path, writer: u32, title: &str, verdict: Trit) -> Journal {
    let _ = std::fs::remove_file(path);
    let mut j = Journal::create_as(path, title, writer).unwrap();
    let n = j.spawn(NodeId(0), NodeKind::Delta, title).unwrap();
    j.record(n, verdict, None, "初始").unwrap();
    drop(j.into_dag().unwrap());
    Journal::open_as(path, writer).unwrap()
}

#[test]
fn negative_lands_persists_and_tightens_gate() {
    let (pa, pb) = (tmp("a", 1), tmp("b", 1));
    let mut fleet = Fleet::new();
    fleet.add("up", make_repo(&pa, 0, "上游库", Trit::Vulnerable)).unwrap();
    fleet.add("down", make_repo(&pb, 1, "下游应用", Trit::Hardened)).unwrap();
    fleet
        .add_cross_link(("up", NodeId(1)), ("down", NodeId(1)), Trit::Vulnerable, "确认穿透")
        .unwrap();

    // 反熵：-1 沿边落账
    let landed: Vec<CrossRepoDelta> = fleet.sync_cross_repo("跨仓反熵").unwrap();
    assert_eq!(landed.len(), 1);
    assert_eq!(landed[0].verdict, Trit::Vulnerable);
    assert_eq!(landed[0].from, ("up".to_string(), NodeId(1)));
    assert_eq!(landed[0].to, ("down".to_string(), NodeId(1)));

    // 落账是目标仓自己的 Delta：独立重开仍可见（持久化），带溯源 note
    drop(fleet);
    let j2 = Journal::open_as(&pb, 1).unwrap();
    let node = j2.dag().node(NodeId(1));
    assert_eq!(node.verdict, Trit::Vulnerable, "跨仓 -1 已入账");
    assert!(
        node.history.iter().any(|e| e.note.contains("up:1")),
        "溯源 note 应指向源仓"
    );
    drop(j2);
    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
}

#[test]
fn plus_one_never_lands_across_repos() {
    let (pa, pb) = (tmp("a", 2), tmp("b", 2));
    let mut fleet = Fleet::new();
    // 源通过 + 穿透边：max(+1, -1) = +1 → 不落
    fleet.add("up", make_repo(&pa, 0, "上游", Trit::Hardened)).unwrap();
    fleet.add("down", make_repo(&pb, 1, "下游", Trit::Unknown)).unwrap();
    fleet
        .add_cross_link(("up", NodeId(1)), ("down", NodeId(1)), Trit::Vulnerable, "穿透边")
        .unwrap();
    let landed = fleet.sync_cross_repo("反熵").unwrap();
    assert!(landed.is_empty(), "源 +1 不得给下游 +1，实际 {landed:?}");
    assert_eq!(fleet.repo_verdict("down", NodeId(1)).unwrap(), Trit::Unknown);

    // 拦截边：已证拦截 → 坏消息也过不来
    let (pc, pd) = (tmp("c", 2), tmp("d", 2));
    fleet.add("up2", make_repo(&pc, 2, "上游2", Trit::Vulnerable)).unwrap();
    fleet.add("down2", make_repo(&pd, 3, "下游2", Trit::Unknown)).unwrap();
    fleet
        .add_cross_link(("up2", NodeId(1)), ("down2", NodeId(1)), Trit::Hardened, "已证拦截")
        .unwrap();
    let landed2 = fleet.sync_cross_repo("反熵").unwrap();
    assert!(landed2.is_empty(), "拦截边不落坏消息，实际 {landed2:?}");
    drop(fleet);
    for p in [&pa, &pb, &pc, &pd] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn sync_is_idempotent_and_never_whitewashes() {
    let (pa, pb) = (tmp("a", 3), tmp("b", 3));
    let mut fleet = Fleet::new();
    fleet.add("up", make_repo(&pa, 0, "上游", Trit::Vulnerable)).unwrap();
    fleet.add("down", make_repo(&pb, 1, "下游", Trit::Hardened)).unwrap();
    fleet
        .add_cross_link(("up", NodeId(1)), ("down", NodeId(1)), Trit::Vulnerable, "穿透")
        .unwrap();

    assert_eq!(fleet.sync_cross_repo("第一次").unwrap().len(), 1);
    assert!(fleet.sync_cross_repo("第二次").unwrap().is_empty(), "幂等");
    assert!(fleet.sync_cross_repo("第三次").unwrap().is_empty(), "幂等");

    // 不覆盖：目标已是 -1（更坏/相等），上游可疑 0 不得洗白也不得重复落
    fleet.record_repo("up", NodeId(1), Trit::Unknown, "上游复查降级").unwrap();
    let landed = fleet.sync_cross_repo("降级传播").unwrap();
    assert!(landed.is_empty(), "max(0,-1)=0 ≥ 目标-1，不落不洗白");
    drop(fleet);
    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
}

#[test]
fn ledger_agrees_with_query_semantics() {
    let (pa, pb) = (tmp("a", 4), tmp("b", 4));
    let mut fleet = Fleet::new();
    fleet.add("up", make_repo(&pa, 0, "上游", Trit::Vulnerable)).unwrap();
    fleet.add("down", make_repo(&pb, 1, "下游", Trit::Hardened)).unwrap();
    fleet
        .add_cross_link(("up", NodeId(1)), ("down", NodeId(1)), Trit::Vulnerable, "穿透")
        .unwrap();

    // 落账前：查询时传播已显示污染（视图）
    assert_eq!(fleet.effective_verdicts("down").unwrap()[1], Trit::Vulnerable);
    // 落账后：账目与查询一致（事实 = 视图，无矛盾）
    fleet.sync_cross_repo("反熵").unwrap();
    assert_eq!(fleet.effective_verdicts("down").unwrap()[1], Trit::Vulnerable);
    drop(fleet);
    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
}

#[test]
fn unknown_repos_and_oob_nodes_are_skipped() {
    let (pa, pb) = (tmp("a", 5), tmp("b", 5));
    let mut fleet = Fleet::new();
    fleet.add("up", make_repo(&pa, 0, "上游", Trit::Vulnerable)).unwrap();
    fleet.add("down", make_repo(&pb, 1, "下游", Trit::Hardened)).unwrap();

    // 非法边从注册表加载进来（加载期不验证——与仓状态解耦的真实形态）：
    // 幽灵源仓 / 源节点越界 / 目标节点越界
    let ledger = std::env::temp_dir().join(format!("trit-cross-ledger-{}.tsv", std::process::id()));
    std::fs::write(
        &ledger,
        "FLEETLINK\tghost\t1\tdown\t1\t-1\t幽灵源\n\
         FLEETLINK\tup\t99\tdown\t1\t-1\t源节点越界\n\
         FLEETLINK\tup\t1\tdown\t99\t-1\t目标越界\n",
    )
    .unwrap();
    let (loaded, skipped) = fleet.load_links(&ledger).unwrap();
    assert_eq!((loaded, skipped), (3, 0), "三条边都加载（不验证）");

    // 反熵期如实跳过：不炸、不落账
    let landed = fleet.sync_cross_repo("反熵").unwrap();
    assert!(landed.is_empty(), "非法边全部跳过，实际 {landed:?}");
    drop(fleet);
    let _ = std::fs::remove_file(&pa);
    let _ = std::fs::remove_file(&pb);
    let _ = std::fs::remove_file(&ledger);
}
