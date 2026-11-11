//! 两线合流的舰队级演练（真实 JSONL 夹具内联——2026-11-05 实测产物）：
//! 逆向（trit-re `triage --jsonl`）→ 桥（[`trit_immune::retbridge::intake_triage`]）
//! → 两仓账本 → 跨仓污染（`sync_cross_repo`）→ 舰队排活（修上游纪律）。
//!
//! 夹具出处：vendor = mingw 编译 trit-re 的 `inject_sample.c` 夹具（真注入能力，
//! 4 条 True 判定）；app = notepad.exe（干净，9 条 False）。**样本只做静态
//! 分析，从未执行。**

use trit_immune::fleet::{family_tasks_fleet, is_imported};
use trit_immune::retbridge::intake_triage;
use trit_immune::{Fleet, Journal, NodeId, Trit};

const VENDOR_JSONL: &str = concat!(
    r#"{"kind":"file","schema":3,"sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","size":34415,"format":"pe32+","arch":"x86-64","sections":9,"imported_functions":33,"xref_complete":true,"xref_referenced":30,"xref_unreferenced":3,"xref_unknown":0}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"packed","title":"结构像加壳/压缩（高熵、壳节名、入口异常或高熵叠加段）","value":"false","four":"N","support":[],"refute":["authenticode.present","entry.outside_code","overlay.high_entropy","packer.section_name","section.high_entropy"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"injection","title":"远程注入能力（申请+写+执行三件套齐备）","value":"true","four":"T","support":["imports.inj.alloc","imports.inj.exec","imports.inj.write"],"refute":[],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"staged_loader","title":"分阶段装载（运行期装载 + 网络）","value":"false","four":"F","support":[],"refute":["imports.loader","imports.network"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"credential_theft","title":"凭据窃取面（凭据 API + 网络外发）","value":"false","four":"F","support":[],"refute":["imports.credential","imports.network"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"fn_injection","title":"同一函数内完成注入三件套（申请 + 写 + 执行）","value":"true","four":"T","support":["fn.injection_cooccur"],"refute":[],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"fn_stager","title":"同一函数内装载 + 网络（典型 stager）","value":"false","four":"F","support":[],"refute":["fn.stager_cooccur"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"fn_credential_exfil","title":"同一函数内读凭据并外发","value":"false","four":"F","support":[],"refute":["fn.credential_cooccur"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"xref_gaps","title":"存在没有静态调用点的导入（可能动态解析或死导入）","value":"true","four":"T","support":["xref.has_unreferenced"],"refute":[],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"c09cb09470dd40171e38162fddf84f4e4affbdca8a70c4a7650acc2655fc7ed3","id":"needs_review","title":"需要人工复核","value":"true","four":"T","support":["injection"],"refute":["credential_theft","packed","staged_loader"],"unknown":[]}"#,
);

const APP_JSONL: &str = concat!(
    r#"{"kind":"file","schema":3,"sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","size":356352,"format":"pe32+","arch":"x86-64","sections":8,"imported_functions":315,"xref_complete":true,"xref_referenced":314,"xref_unreferenced":0,"xref_unknown":1}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"packed","title":"结构像加壳/压缩（高熵、壳节名、入口异常或高熵叠加段）","value":"false","four":"N","support":[],"refute":["authenticode.present","entry.outside_code","overlay.high_entropy","packer.section_name","section.high_entropy"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"injection","title":"远程注入能力（申请+写+执行三件套齐备）","value":"false","four":"F","support":["imports.inj.alloc"],"refute":["imports.inj.exec","imports.inj.write"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"staged_loader","title":"分阶段装载（运行期装载 + 网络）","value":"false","four":"F","support":["imports.loader"],"refute":["imports.network"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"credential_theft","title":"凭据窃取面（凭据 API + 网络外发）","value":"false","four":"F","support":["imports.credential"],"refute":["imports.network"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"fn_injection","title":"同一函数内完成注入三件套（申请 + 写 + 执行）","value":"false","four":"F","support":[],"refute":["fn.injection_cooccur"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"fn_stager","title":"同一函数内装载 + 网络（典型 stager）","value":"false","four":"F","support":[],"refute":["fn.stager_cooccur"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"fn_credential_exfil","title":"同一函数内读凭据并外发","value":"false","four":"F","support":[],"refute":["fn.credential_cooccur"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"xref_gaps","title":"存在没有静态调用点的导入（可能动态解析或死导入）","value":"false","four":"F","support":[],"refute":["xref.has_unreferenced"],"unknown":[]}"#,
    "\n",
    r#"{"kind":"judgment","sha256":"87ca8213820a0ecac9cd131b5e6be9268a56e4e121482a5816ee7baefc9ce042","id":"needs_review","title":"需要人工复核","value":"false","four":"N","support":[],"refute":["credential_theft","injection","packed","staged_loader"],"unknown":[]}"#,
);

fn temp_path(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "retbridge-fleet-{tag}-{}-{n}.tritj",
        std::process::id()
    ))
}

/// 全链路：桥 → 两仓 → 跨仓污染 → 舰队排活（修上游 + 回声抑制）。
#[test]
fn fleet_drill_upstream_fix_downstream_echo_suppressed() {
    // ① 桥：真实台账入账。vendor 外部输入自动隔离（人工复核前不放行）；
    //    app 放行（quarantine=false）——为的是让排活语义显形。
    let pv = temp_path("vendor");
    let mut vendor_j = Journal::create_as(&pv, "vendor", 0).expect("建 vendor 账");
    let vr = intake_triage(&mut vendor_j, NodeId(0), VENDOR_JSONL, true).expect("桥 vendor");
    assert_eq!(vr.samples, 1);
    assert_eq!(
        vr.vulnerable, 4,
        "真注入样本 4 条 True 全部 -1（injection/fn_injection/xref_gaps/needs_review）"
    );
    assert_eq!(vr.skipped_false, 5, "5 条 False 不入账（扫描器永不 +1）");
    assert_eq!(vr.quarantined, 5, "样本+4 发现全隔离");
    drop(vendor_j.into_dag().expect("落盘"));

    let pa = temp_path("app");
    let mut app_j = Journal::create_as(&pa, "app", 1).expect("建 app 账");
    let ar = intake_triage(&mut app_j, NodeId(0), APP_JSONL, false).expect("桥 app");
    assert_eq!(ar.findings, 0, "干净样本零发现——False 全部不入账");
    drop(app_j.into_dag().expect("落盘"));

    // ② 舰队：跨仓边 = app 内嵌 vendor 的注入组件（确认穿透）
    let mut fleet = Fleet::new();
    fleet
        .add("vendor", Journal::open_as(&pv, 0).expect("重开"))
        .expect("入队");
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");
    fleet
        .add_cross_link(
            ("vendor", NodeId(2)), // injection = -1 的发现节点
            ("app", NodeId(1)),    // app 的样本组件节点（0 态）
            Trit::Vulnerable,
            "app 内嵌 vendor 的注入组件",
        )
        .expect("声明边");
    let landed = fleet.sync_cross_repo("舰队演练").expect("反熵");
    assert_eq!(landed.len(), 1, "污染落账一条");
    assert_eq!(landed[0].verdict, Trit::Vulnerable);

    // ③ 落账事实：app#1 被拉成 -1，带落账标记可溯源（变坏才落账）
    let app_dag = fleet.get("app").expect("app 在队").dag().clone();
    assert_eq!(
        app_dag.node(NodeId(1)).verdict,
        Trit::Vulnerable,
        "下游被上游打穿"
    );
    assert!(is_imported(&app_dag, NodeId(1)), "落账标记在案");
    assert!(
        app_dag
            .node(NodeId(1))
            .history
            .last()
            .expect("有事件")
            .note
            .contains("← vendor:2"),
        "溯源到上游发现节点"
    );

    // ④ 舰队排活：修上游——下游回声不排活（上游修好反熵自愈）
    let tasks = family_tasks_fleet(&fleet);
    assert!(
        !tasks.iter().any(|t| t.repo == "app"),
        "app 的唯一发现是导入回声——不排活：{tasks:?}"
    );
    // vendor 全仓隔离（外部输入待人工复核）→ 节点级 Review 保留（5 个隔离节点）
    let vendor_tasks: Vec<_> = tasks.iter().filter(|t| t.repo == "vendor").collect();
    assert_eq!(vendor_tasks.len(), 5, "vendor 5 个隔离节点各一条 Review");
    assert!(
        vendor_tasks
            .iter()
            .all(|t| matches!(t.task, trit_immune::scheduler::Task::Review { .. })),
        "隔离节点只产 Review（人工复核是唯一出口）"
    );

    let _ = std::fs::remove_file(&pv);
    let _ = std::fs::remove_file(&pa);
}

/// 复盘视图：同一次演练里，fleet 级目录应把两个样本各自成族
/// （根因不同不分族——宁可分开不静默合并错）。
#[test]
fn fleet_catalog_separates_the_two_samples() {
    let pv = temp_path("vendor");
    let mut vendor_j = Journal::create_as(&pv, "vendor", 0).expect("建 vendor 账");
    intake_triage(&mut vendor_j, NodeId(0), VENDOR_JSONL, false).expect("桥 vendor");
    drop(vendor_j.into_dag().expect("落盘"));
    let pa = temp_path("app");
    let mut app_j = Journal::create_as(&pa, "app", 1).expect("建 app 账");
    intake_triage(&mut app_j, NodeId(0), APP_JSONL, false).expect("桥 app");
    drop(app_j.into_dag().expect("落盘"));

    let mut fleet = Fleet::new();
    fleet
        .add("vendor", Journal::open_as(&pv, 0).expect("重开"))
        .expect("入队");
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");

    // vendor（quarantine=false 重桥）：4 条 -1 全在目录，未隔离 → 可评估
    let vendor_dag = fleet.get("vendor").expect("在队").dag().clone();
    let cat = trit_immune::catalog(&vendor_dag);
    assert_eq!(cat.stats.findings, 5, "样本 + 4 判定全在目录");
    assert_eq!(
        cat.entries
            .iter()
            .filter(|e| e.verdict == Trit::Vulnerable)
            .count(),
        4,
        "4 条 -1"
    );
    assert!(
        cat.families
            .iter()
            .any(|f| f.signature.contains("injection") && f.verdict == Trit::Vulnerable),
        "injection 族 -1 在案：{:?}",
        cat.families
            .iter()
            .map(|f| &f.signature)
            .collect::<Vec<_>>()
    );

    // app：零发现（False 不入账）→ 目录只有样本的 0 态族
    let app_dag = fleet.get("app").expect("在队").dag().clone();
    let cat = trit_immune::catalog(&app_dag);
    assert_eq!(cat.stats.findings, 1, "干净样本只有样本身份一个条目");
    assert_eq!(cat.entries[0].verdict, Trit::Unknown, "0 态");

    let _ = std::fs::remove_file(&pv);
    let _ = std::fs::remove_file(&pa);
}

#[test]
fn fleet_poisoned_verdict_meets_human_adjudication() {
    // MEMETIC-RESISTANCE 想法一（舰队级实验）：投毒 -1 经跨仓边遭遇
    // 人工 +1。钉死现状语义：sync 的「变坏才落账」把 Vulnerable 视为
    // 比 Hardened 更坏 → 覆盖人工裁决；history 保留完整序列 → 目录
    // **Refuted 显式告警**（污染不静默）。改进想法（如实记录）：
    // Hardened 后的跨仓落账应要求重新人工确认，而不是直接翻转。
    let pv = temp_path("poison-vendor");
    let mut vendor_j = Journal::create_as(&pv, "pvendor", 0).expect("建 vendor 账");
    // 不隔离 = 污染直接可用（模拟被攻陷的 upstream）
    let vr = intake_triage(&mut vendor_j, NodeId(0), VENDOR_JSONL, false).expect("桥 vendor");
    assert_eq!(vr.vulnerable, 4);
    drop(vendor_j.into_dag().expect("落盘"));

    let pa = temp_path("poison-app");
    let mut app_j = Journal::create_as(&pa, "papp", 1).expect("建 app 账");
    let _ar = intake_triage(&mut app_j, NodeId(0), APP_JSONL, false).expect("桥 app");
    // 人工裁决：样本节点 Hardened（人工复核确认为良性）
    app_j
        .record(NodeId(1), Trit::Hardened, None, "人工复核：样本确认为良性")
        .expect("人工裁决");
    assert_eq!(app_j.dag().node(NodeId(1)).verdict, Trit::Hardened);
    drop(app_j.into_dag().expect("落盘"));

    let mut fleet = Fleet::new();
    fleet
        .add("vendor", Journal::open_as(&pv, 0).expect("重开"))
        .expect("入队");
    fleet
        .add("app", Journal::open_as(&pa, 1).expect("重开"))
        .expect("入队");
    fleet
        .add_cross_link(
            ("vendor", NodeId(2)), // injection 发现节点（-1）
            ("app", NodeId(1)),    // app 样本节点（已被人工 Hardened）
            Trit::Vulnerable,
            "投毒跨仓边",
        )
        .expect("声明边");
    let landed = fleet.sync_cross_repo("投毒演练").expect("反熵");
    assert_eq!(landed.len(), 1, "Hardened → Vulnerable 算变坏：现状落账");

    // 目录面：history = [Hardened, Vulnerable] → **Refuted 显式告警**
    let app_dag = fleet.get("app").expect("app 在队").dag().clone();
    assert_eq!(app_dag.node(NodeId(1)).verdict, Trit::Vulnerable);
    let hist: Vec<Trit> = app_dag
        .node(NodeId(1))
        .history
        .iter()
        .map(|e| e.verdict)
        .collect();
    assert_eq!(
        hist,
        vec![Trit::Unknown, Trit::Hardened, Trit::Vulnerable],
        "0 态初始 + 人工裁决 + 污染落账——修正不删除"
    );
    let cat = trit_immune::catalog(&app_dag);
    let correction = cat
        .corrections
        .iter()
        .find(|x| x.node == NodeId(1))
        .expect("修正被记录");
    assert_eq!(
        correction.kind,
        trit_immune::CorrectionKind::Refuted,
        "模因污染显式告警（想法一核心断言）"
    );

    let _ = std::fs::remove_file(&pv);
    let _ = std::fs::remove_file(&pa);
}
