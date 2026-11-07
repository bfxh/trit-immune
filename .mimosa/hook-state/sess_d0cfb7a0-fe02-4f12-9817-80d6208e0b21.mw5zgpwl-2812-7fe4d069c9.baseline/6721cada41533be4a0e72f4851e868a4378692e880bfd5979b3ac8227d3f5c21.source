//! # retbridge —— trit-re 逆向台账 → 裁决账本的桥
//!
//! trit-re（逆向台账，`triage --jsonl`）的产出吃进裁决账本：
//! 逆向发现 → 裁决入账 → 传播/门禁/目录——两条网安线在账本上合成一个系统。
//!
//! ## 三值语义对齐表（trit-re → trit-immune）
//!
//! | trit-re 判定 | trit-immune 裁决 | 语义 |
//! |---|---|---|
//! | `true` | `Vulnerable`(-1) | 能力确认（静态分析确认，扫描语义） |
//! | `unknown` | `Unknown`(0) | 没看见——"没看见"原样传递 |
//! | `false` | **不入账** | **扫描器永不 +1**：静态 False 非安全证明 |
//!
//! `False` 不入账是本桥最重要的纪律：静态分析说"没看见注入三件套"不等于
//! "安全"（动态解析、混淆、未知向量都在 `False` 的盲区里）——把 `False`
//! 记成 +1 就是给账本灌洗白水。
//!
//! ## 入账形态
//!
//! - `file` 行 → Message 节点（样本身份，**0 态**：外部输入未测不可信）；
//! - `judgment` 行 → 样本节点下的发现节点（title = 判定 id，note 带全量
//!   证据：title/support/refute/four——账外无数据）；
//! - 全部 note 前缀 `trit-re:<sha256>`——可溯源到逆向台账的原样输出；
//! - 外部输入自动隔离（与 [`crate::intake`] 同一条数据转移桥纪律）：
//!   隔离拦放行不抹裁决，人工复核后原状态恢复。
//!
//! `fact`/`xref`/`function` 行 v1 不入账（fact 是中性观察，xref/function
//! 是过程数据）——如实计数，需要时再扩。
//!
//! ```
//! use trit_immune::{Journal, NodeId, retbridge::intake_triage};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut j = Journal::create_as(&std::env::temp_dir().join("retbridge-doc.tritj"), "doc", 0)?;
//! let jsonl = concat!(
//!     r#"{"kind":"file","schema":3,"sha256":"abc","size":10}"#, "\n",
//!     r#"{"kind":"judgment","sha256":"abc","id":"injection","title":"远程注入","value":"true","four":"F","support":["imports.inj.alloc"],"refute":[],"unknown":[]}"#, "\n",
//! );
//! let report = intake_triage(&mut j, NodeId(0), jsonl, true)?;
//! assert_eq!(report.samples, 1);
//! assert_eq!(report.vulnerable, 1, "true → -1");
//! assert_eq!(report.quarantined, 2, "外部输入自动隔离（样本+发现）");
//! # std::fs::remove_file(std::env::temp_dir().join("retbridge-doc.tritj")).ok();
//! # Ok(())
//! # }
//! ```

use crate::journal::Journal;
use crate::json::Json;
use crate::NodeId;
use crate::NodeKind;
use crate::Trit;
use std::io;

/// 一次台账入账的报告（全部计数如实，坏行不中断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TriageIntakeReport {
    /// `file` 行立的样本节点数。
    pub samples: usize,
    /// judgment 入账数（`-1`/`0` 之和）。
    pub findings: usize,
    /// `-1`（能力确认）数。
    pub vulnerable: usize,
    /// `0`（声称/没看见）数。
    pub unknown: usize,
    /// `False` 判定不入账数（**扫描器永不 +1**）。
    pub skipped_false: usize,
    /// 自动隔离的节点数。
    pub quarantined: usize,
    /// 非法 JSONL 行数（如实计数不中断）。
    pub bad_lines: usize,
}

/// 把 trit-re 的 JSONL 台账吃进账本：`parent` 下立样本节点（`file` 行），
/// `judgment` 行按三值对齐表入账，外部输入自动隔离。
pub fn intake_triage(
    journal: &mut Journal,
    parent: NodeId,
    jsonl_text: &str,
    quarantine: bool,
) -> io::Result<TriageIntakeReport> {
    let mut report = TriageIntakeReport::default();
    // sha256 → 样本节点（file 行先于 judgment 行，但防御性支持乱序）
    let mut sample_of: std::collections::BTreeMap<String, NodeId> =
        std::collections::BTreeMap::new();
    let mut deferred: Vec<(String, JudgmentRow)> = Vec::new();

    for (lineno, line) in jsonl_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed = match crate::json::parse(line) {
            Ok(json) => json,
            Err(reason) => {
                report.bad_lines += 1;
                eprintln!("retbridge：第 {lineno} 行非合法 JSON，如实跳过：{reason}");
                continue;
            }
        };
        let kind = parsed.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        match kind {
            "file" => {
                let Some(sha) = parsed.get("sha256").and_then(|v| v.as_str()) else {
                    report.bad_lines += 1;
                    continue;
                };
                let size = parsed
                    .get("size")
                    .and_then(|v| v.as_f64())
                    .map(|n| n as u64)
                    .unwrap_or(0);
                let node = journal
                    .spawn(parent, NodeKind::Message, &format!("trit-re 样本 {sha}"))
                    .map_err(|e| io::Error::other(e.to_string()))?;
                journal
                    .record(
                        node,
                        Trit::Unknown,
                        None,
                        &format!("trit-re:<{sha}> 逆向台账入账（{size} 字节）——未测不可信"),
                    )
                    .map_err(|e| io::Error::other(e.to_string()))?;
                sample_of.insert(sha.to_string(), node);
                report.samples += 1;
            }
            "judgment" => match JudgmentRow::from_json(&parsed) {
                Some(row) => {
                    let sha = row.sha.clone();
                    deferred.push((sha, row));
                }
                None => report.bad_lines += 1,
            },
            // fact/xref/function：v1 不入账，如实存在即可（调用方看行数）
            _ => {}
        }
    }

    // judgment 落账（file 行全部处理完后——保证样本节点已在）
    for (sha, row) in deferred {
        let sample = match sample_of.get(&sha) {
            Some(node) => *node,
            None => {
                // judgment 先于 file 行：样本节点按需立（账外无孤行）
                let node = journal
                    .spawn(parent, NodeKind::Message, &format!("trit-re 样本 {sha}"))
                    .map_err(|e| io::Error::other(e.to_string()))?;
                journal
                    .record(
                        node,
                        Trit::Unknown,
                        None,
                        &format!(
                            "trit-re:<{sha}> 逆向台账入账（judgment 先行，file 行缺）——未测不可信"
                        ),
                    )
                    .map_err(|e| io::Error::other(e.to_string()))?;
                sample_of.insert(sha.clone(), node);
                report.samples += 1;
                *sample_of.get(&sha).expect("刚插入")
            }
        };
        let verdict = match row.value.as_str() {
            "true" => {
                report.vulnerable += 1;
                Some(Trit::Vulnerable)
            }
            "unknown" => {
                report.unknown += 1;
                Some(Trit::Unknown)
            }
            _ => {
                report.skipped_false += 1;
                None // False 不入账：扫描器永不 +1
            }
        };
        let Some(verdict) = verdict else {
            continue;
        };
        let node = journal
            .spawn(
                sample,
                NodeKind::Message,
                &format!("trit-re 判定: {}", row.id),
            )
            .map_err(|e| io::Error::other(e.to_string()))?;
        let note = format!(
            "trit-re:<{}> {}（four={}）支持={:?} 反驳={:?} 未决={:?}",
            row.sha, row.title, row.four, row.support, row.refute, row.undecided
        );
        journal
            .record(node, verdict, None, &note)
            .map_err(|e| io::Error::other(e.to_string()))?;
        report.findings += 1;
    }

    // 外部输入自动隔离：parent 的直系未放行子节点各拉一条隔离
    // （quarantine 级联子树，孙辈经样本节点一并冻结）；计数 = 事后如实清点
    // 「本次入账的、parent 子树内、处于隔离态」的节点。
    if quarantine {
        let to_quarantine: Vec<NodeId> = journal
            .dag()
            .nodes()
            .iter()
            .filter(|n| {
                n.id != parent
                    && !n.quarantined
                    && n.verdict != Trit::Hardened
                    && n.parent == Some(parent)
            })
            .map(|n| n.id)
            .collect();
        for id in to_quarantine {
            journal
                .quarantine(id, "外部逆向台账自动隔离（retbridge 管线）")
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        report.quarantined = journal
            .dag()
            .nodes()
            .iter()
            .filter(|n| {
                n.quarantined && n.id != parent && is_within_subtree(journal.dag(), n.id, parent)
            })
            .count();
    }
    Ok(report)
}

/// `id` 是否在 `root` 的子树内（沿父链上溯）。
fn is_within_subtree(dag: &crate::dag::ImmuneDag, id: NodeId, root: NodeId) -> bool {
    let mut cur = Some(id);
    while let Some(node_id) = cur {
        if node_id == root {
            return true;
        }
        cur = dag.node(node_id).parent;
    }
    false
}

struct JudgmentRow {
    sha: String,
    id: String,
    title: String,
    value: String,
    four: String,
    support: Vec<String>,
    refute: Vec<String>,
    undecided: Vec<String>,
}

impl JudgmentRow {
    fn from_json(json: &Json) -> Option<Self> {
        let sha = json.get("sha256")?.as_str()?.to_string();
        let id = json.get("id")?.as_str()?.to_string();
        let title = json.get("title")?.as_str()?.to_string();
        let value = json.get("value")?.as_str()?.to_string();
        let four = json
            .get("four")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let list = |key: &str| -> Vec<String> {
            json.get(key)
                .and_then(|v| v.as_arr())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(Self {
            sha,
            id,
            title,
            value,
            four,
            support: list("support"),
            refute: list("refute"),
            undecided: list("unknown"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_journal(tag: &str) -> (Journal, std::path::PathBuf) {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("retbridge-{tag}-{}-{n}.tritj", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let j = Journal::create_as(&path, "main", 0).expect("建账");
        (j, path)
    }

    const SAMPLE_JSONL: &str = concat!(
        r#"{"kind":"file","schema":3,"sha256":"cafe01","size":100,"format":"pe32+","arch":"x86-64","sections":5}"#,
        "\n",
        r#"{"kind":"judgment","sha256":"cafe01","id":"injection","title":"远程注入能力","value":"true","four":"F","support":["imports.inj.alloc","imports.inj.write"],"refute":[],"unknown":[]}"#,
        "\n",
        r#"{"kind":"judgment","sha256":"cafe01","id":"packed","title":"结构像加壳","value":"unknown","four":"X","support":[],"refute":[],"unknown":["overlay.high_entropy"]}"#,
        "\n",
        r#"{"kind":"judgment","sha256":"cafe01","id":"clean_rtti","title":"RTTI 完整","value":"false","four":"N","support":[],"refute":["rtti.present"],"unknown":[]}"#,
        "\n",
        "这行不是 JSON\n",
    );

    #[test]
    fn triage_jsonl_bridges_verdicts() {
        let (mut j, path) = temp_journal("bridge");
        let report = intake_triage(&mut j, NodeId(0), SAMPLE_JSONL, true).expect("入账");
        assert_eq!(report.samples, 1);
        assert_eq!(report.findings, 2, "true + unknown 入账，false 不入账");
        assert_eq!(report.vulnerable, 1);
        assert_eq!(report.unknown, 1);
        assert_eq!(report.skipped_false, 1, "扫描器永不 +1：False 不入账");
        assert_eq!(report.bad_lines, 1, "坏行如实计数不中断");
        assert_eq!(report.quarantined, 3, "样本+2 发现全隔离");
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn false_verdicts_never_create_hardened_nodes() {
        // 本桥的头条纪律：扫描器永不 +1——False 不产生任何 Hardened 节点
        // （root 基线节点除外——那是账本自带的 +1 起点，不是桥产的）
        let (mut j, path) = temp_journal("nofalse");
        intake_triage(&mut j, NodeId(0), SAMPLE_JSONL, false).expect("入账");
        for n in j.dag().nodes().iter().skip(1) {
            assert_ne!(
                n.verdict,
                Trit::Hardened,
                "节点 #{} 不该是 Hardened（扫描器永不 +1）",
                n.id.0
            );
        }
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn findings_are_children_of_sample_with_lineage() {
        let (mut j, path) = temp_journal("lineage");
        intake_triage(&mut j, NodeId(0), SAMPLE_JSONL, false).expect("入账");
        let dag = j.dag().clone();
        let sample = &dag.nodes()[1];
        assert!(
            sample.title.contains("trit-re 样本 cafe01"),
            "样本节点带 sha 溯源：{}",
            sample.title
        );
        let children: Vec<_> = dag
            .nodes()
            .iter()
            .filter(|n| n.parent == Some(sample.id))
            .collect();
        assert_eq!(children.len(), 2, "true + unknown 两条发现挂在样本下");
        for child in &children {
            assert!(
                child.title.starts_with("trit-re 判定: "),
                "发现节点 title 带判定 id"
            );
            let note = &child.history.last().expect("有裁决事件").note;
            assert!(
                note.contains("trit-re:<cafe01>"),
                "note 可溯源到逆向台账：{note}"
            );
        }
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn quarantine_freezes_merge_gate() {
        // 隔离拦放行：样本节点（及其子树）在人工复核前不得放行。
        // 父节点门禁不受隔离子树殃及——"兄弟分支不殃及"是特性不是缺陷。
        let (mut j, path) = temp_journal("gate");
        intake_triage(&mut j, NodeId(0), SAMPLE_JSONL, true).expect("入账");
        let dag = j.dag().clone();
        let sample = dag
            .nodes()
            .iter()
            .find(|n| n.title.contains("trit-re 样本 cafe01"))
            .expect("样本节点在账")
            .id;
        assert!(dag.node(sample).quarantined, "样本节点处于隔离态");
        assert_eq!(
            dag.merge_gate(sample),
            crate::verdict::GateDecision::Freeze,
            "隔离态样本 → 冻结（人工复核前不放行）"
        );
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn judgment_before_file_still_bridges() {
        // 乱序防御：judgment 先于 file 行，样本节点按需立
        let (mut j, path) = temp_journal("order");
        let jsonl = concat!(
            r#"{"kind":"judgment","sha256":"dead02","id":"packed","title":"加壳","value":"true","four":"F","support":[],"refute":[],"unknown":[]}"#,
            "\n",
            r#"{"kind":"file","schema":3,"sha256":"dead02","size":7}"#,
            "\n",
        );
        let report = intake_triage(&mut j, NodeId(0), jsonl, false).expect("入账");
        assert_eq!(report.samples, 1, "file 行不重复立节点");
        assert_eq!(report.vulnerable, 1);
        let dag = j.dag().clone();
        let samples: Vec<_> = dag
            .nodes()
            .iter()
            .filter(|n| n.title.contains("trit-re 样本 dead02"))
            .collect();
        assert_eq!(samples.len(), 1, "乱序不产生孤儿/重复样本节点");
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_and_malformed_input_fail_closed() {
        let (mut j, path) = temp_journal("empty");
        let report = intake_triage(&mut j, NodeId(0), "", false).expect("空输入不是错");
        assert_eq!(report, TriageIntakeReport::default());
        let garbage = "}{ 不是 json \n\n{broken";
        let report = intake_triage(&mut j, NodeId(0), garbage, false).expect("垃圾输入不是错");
        assert_eq!(report.bad_lines, 2, "坏行计数（空行不计）");
        assert_eq!(report.samples, 0);
        assert_eq!(report.findings, 0);
        drop(j.into_dag().expect("落盘"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn replay_consistency_with_real_pipeline() {
        // 实时入账 vs 全量重放：桥的产物走同一条 apply 路径
        let (mut j, path) = temp_journal("replay");
        intake_triage(&mut j, NodeId(0), SAMPLE_JSONL, true).expect("入账");
        let live_dag = j.dag().clone();
        drop(j.into_dag().expect("落盘"));

        // 重放同一份日志（行 = `ts\tdelta`，parse_stamped_line 原样吃）
        let text = std::fs::read_to_string(&path).expect("读日志");
        let mut replayed = crate::dag::ImmuneDag::empty();
        for line in text.lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let Ok((_, delta)) = crate::journal::parse_stamped_line(line) else {
                continue;
            };
            replayed.apply(&delta).expect("重放成功");
        }
        assert_eq!(
            live_dag.nodes().len(),
            replayed.nodes().len(),
            "重放节点数一致（桥不改账本语义）"
        );
        for (live, back) in live_dag.nodes().iter().zip(replayed.nodes().iter()) {
            assert_eq!(live.title, back.title);
            assert_eq!(live.verdict, back.verdict);
            assert_eq!(live.quarantined, back.quarantined);
        }
        let _ = std::fs::remove_file(&path);
    }
}
