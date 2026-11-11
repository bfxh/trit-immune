//! 舰队级 TMR 同步实验（MEMETIC-RESISTANCE 想法三的舰队形态）：
//! 多源跨仓票**先收集后表决**——单引擎投毒无法穿透，人工裁决受保护。

use trit_immune::fleet::Fleet;
use trit_immune::retbridge::intake_triage;
use trit_immune::{Journal, NodeId, Trit};

/// 注入样本 JSONL（vendor 各持一份——三"扫描器"对同一样本各出判定）。
const VENDOR_JSONL: &str = concat!(
    r#"{"kind":"file","schema":3,"sha256":"tmr-vendor-sample","size":7,"format":"pe32+","arch":"x86-64","sections":1,"imported_functions":1,"xref_complete":true,"xref_referenced":1,"xref_unreferenced":0,"xref_unknown":0}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"tmr-vendor-sample","id":"injection","title":"注入","value":"true","four":"T","support":["imports.inj.alloc"],"refute":[],"unknown":[]}"#,
);

fn temp_path(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("fleet-tmr-{tag}-{}-{n}.tritj", std::process::id()))
}

/// 三 vendor 各出一票 -1（佐证成立）→ TMR 落 -1 + 三源溯源注记。
#[test]
fn three_voting_sources_corroborate_vulnerable() {
    let pa = temp_path("app3");
    let mut app_j = Journal::create_as(&pa, "app", 1).expect("建 app 账");
    let _ar = intake_triage(&mut app_j, NodeId(0), VENDOR_JSONL, false).expect("桥 app");
    drop(app_j.into_dag().expect("落盘"));

    let mut fleet = Fleet::new();
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");
    let mut vendor_paths = Vec::new();
    for i in 0..3 {
        let p = temp_path(&format!("v{i}"));
        let mut j = Journal::create_as(&p, &format!("v{i}"), 0).expect("建 vendor 账");
        intake_triage(&mut j, NodeId(0), VENDOR_JSONL, false).expect("桥 vendor");
        drop(j.into_dag().expect("落盘"));
        vendor_paths.push(p.clone());
        fleet
            .add(&format!("v{i}"), Journal::open_as(&p, 0).expect("重开"))
            .expect("入队");
        // 每个 vendor 的注入发现节点（#2）都指向 app 的样本身份节点（#1）
        fleet
            .add_cross_link(
                (&format!("v{i}"), NodeId(2)),
                ("app", NodeId(1)),
                Trit::Vulnerable,
                "三源佐证",
            )
            .expect("声明边");
    }
    let landed = fleet.tmr_sync_cross_repo("舰队 TMR").expect("同步");
    assert_eq!(landed.len(), 3, "三票三 Delta（每个来源一条溯源记录）");
    assert!(
        landed.iter().all(|d| d.verdict == Trit::Vulnerable),
        "佐证成立：全部 -1"
    );

    let app_dag = fleet.get("app").expect("app 在队").dag().clone();
    assert_eq!(app_dag.node(NodeId(1)).verdict, Trit::Vulnerable);
    let last = app_dag.node(NodeId(1)).history.last().expect("有事件");
    assert!(
        last.note.contains("TMR←") && last.note.contains("v_count=3"),
        "三源溯源注记：{}",
        last.note
    );
    for p in vendor_paths {
        let _ = std::fs::remove_file(&p);
    }
    let _ = std::fs::remove_file(&pa);
}

/// 单源声称降权：只有一个 vendor 出 -1 票 → 落 Unknown（投毒抑制面）。
#[test]
fn single_source_vulnerable_downgrades_to_unknown() {
    let pa = temp_path("app1");
    let mut app_j = Journal::create_as(&pa, "app", 1).expect("建 app 账");
    let _ar = intake_triage(&mut app_j, NodeId(0), VENDOR_JSONL, false).expect("桥 app");
    drop(app_j.into_dag().expect("落盘"));

    let pv = temp_path("v0");
    let mut v0 = Journal::create_as(&pv, "v0", 0).expect("建 vendor 账");
    intake_triage(&mut v0, NodeId(0), VENDOR_JSONL, false).expect("桥 vendor");
    drop(v0.into_dag().expect("落盘"));

    let mut fleet = Fleet::new();
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");
    fleet
        .add("v0", Journal::open_as(&pv, 0).expect("重开"))
        .expect("入队");
    fleet
        .add_cross_link(
            ("v0", NodeId(2)),
            ("app", NodeId(1)),
            Trit::Vulnerable,
            "单源",
        )
        .expect("声明边");
    let landed = fleet.tmr_sync_cross_repo("单源演练").expect("同步");
    assert_eq!(landed.len(), 1);
    assert_eq!(
        landed[0].verdict,
        Trit::Unknown,
        "单源 -1 声称降权为 0（投毒抑制面）"
    );

    let app_dag = fleet.get("app").expect("app 在队").dag().clone();
    assert_eq!(app_dag.node(NodeId(1)).verdict, Trit::Unknown);
    assert!(
        app_dag
            .node(NodeId(1))
            .history
            .last()
            .expect("有事件")
            .note
            .contains("v_count=1"),
        "单源降权注记可见"
    );
    let _ = std::fs::remove_file(&pv);
    let _ = std::fs::remove_file(&pa);
}

/// 人工裁决受保护：目标已 Hardened（人工确认良性）→ 跨仓票跳过不翻转。
#[test]
fn hardened_target_is_protected_from_cross_repo_votes() {
    let pa = temp_path("app-protected");
    let mut app_j = Journal::create_as(&pa, "app", 1).expect("建 app 账");
    let _ar = intake_triage(&mut app_j, NodeId(0), VENDOR_JSONL, false).expect("桥 app");
    // 人工裁决：样本节点 Hardened（人工复核确认为良性）
    app_j
        .record(NodeId(1), Trit::Hardened, None, "人工复核：确认为良性")
        .expect("人工裁决");
    assert_eq!(app_j.dag().node(NodeId(1)).verdict, Trit::Hardened);
    drop(app_j.into_dag().expect("落盘"));

    let pv = temp_path("v0");
    let mut v0 = Journal::create_as(&pv, "v0", 0).expect("建 vendor 账");
    intake_triage(&mut v0, NodeId(0), VENDOR_JSONL, false).expect("桥 vendor");
    drop(v0.into_dag().expect("落盘"));

    let mut fleet = Fleet::new();
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");
    fleet
        .add("v0", Journal::open_as(&pv, 0).expect("重开"))
        .expect("入队");
    fleet
        .add_cross_link(
            ("v0", NodeId(2)),
            ("app", NodeId(1)),
            Trit::Vulnerable,
            "单源",
        )
        .expect("声明边");
    // 人工 Hardened 目标：TMR 同步跳过（不翻转）——且不算"变坏落账"
    let landed = fleet.tmr_sync_cross_repo("保护演练").expect("同步");
    assert!(landed.is_empty(), "Hardened 目标无落账");

    let app_dag = fleet.get("app").expect("app 在队").dag().clone();
    assert_eq!(
        app_dag.node(NodeId(1)).verdict,
        Trit::Hardened,
        "人工裁决受保护：不被跨仓票翻转"
    );
    let _ = std::fs::remove_file(&pv);
    let _ = std::fs::remove_file(&pa);
}
