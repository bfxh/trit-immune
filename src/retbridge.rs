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
    /// four=B（Belnap 矛盾）判定数——扫描器内部证据自洽性告警，
    /// 模因矛盾的机器可检测信号（MEMETIC-RESISTANCE 想法一）。
    pub conflicted: usize,
}

/// 三源 TMR 桥的反污染报告（MEMETIC-RESISTANCE 想法三的管线形态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TmrIntakeReport {
    /// `file` 行立的样本节点数（三源并集）。
    pub samples: usize,
    /// TMR 表决落账的发现数。
    pub findings: usize,
    /// **佐证成立**（≥2 源一致 true → `-1`）数。
    pub corroborated: usize,
    /// **单源声称被降级**（仅 1 源 true → `0` + 注记）数——投毒抑制面。
    pub suppressed_single: usize,
    /// 全源 `unknown`（没看见）数。
    pub unknown: usize,
    /// four=B 矛盾告警数（任一源携带即计）。
    pub conflicted: usize,
    /// 非法 JSONL 行数（如实计数不中断）。
    pub bad_lines: usize,
}

/// 值映射（投票口径）：true → Vulnerable 声称；unknown → Unknown 声称；
/// false → **弃权**（扫描器没看见不构成票）。
fn vote_of(value: &str) -> Option<Trit> {
    match value {
        "true" => Some(Trit::Vulnerable),
        "unknown" => Some(Trit::Unknown),
        _ => None,
    }
}

/// **三源 TMR 桥**：三份独立 trit-re JSONL（三个扫描器），按
/// `(sha256, 判定 id)` 配对后 TMR 表决入账。
///
/// 反污染纪律（MEMETIC-RESISTANCE 想法三的管线形态）：
/// - **≥2 源一致 true → `-1`**（佐证成立——单引擎声称无法独立入账）；
/// - 仅 1 源 true → **降级为 `0` + 注记**（投毒抑制面：单源 -1 声称
///   无佐证即降权）；
/// - 全源 `unknown` → `0`（没看见）；全源弃权 → 不入账；
/// - 任一源 `four=B` → 矛盾告警计数（想法一联动）。
pub fn tmr_intake_triage(
    journal: &mut Journal,
    parent: NodeId,
    jsonl_texts: [&str; 3],
    quarantine: bool,
) -> io::Result<TmrIntakeReport> {
    let mut report = TmrIntakeReport::default();
    let mut sample_of: std::collections::BTreeMap<String, NodeId> =
        std::collections::BTreeMap::new();
    let mut deferred: Vec<(String, JudgmentRow)> = Vec::new();

    for text in jsonl_texts {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parsed = match crate::json::parse(line) {
                Ok(j) => j,
                Err(_) => {
                    report.bad_lines += 1;
                    continue;
                }
            };
            match parsed.get("kind").and_then(|v| v.as_str()) {
                Some("file") => {
                    let sha = parsed
                        .get("sha256")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if sha.is_empty() || sample_of.contains_key(&sha) {
                        continue;
                    }
                    let node = journal
                        .spawn(
                            parent,
                            NodeKind::Message,
                            &format!("trit-re 样本 {}", &sha[..16.min(sha.len())]),
                        )
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    journal
                        .record(
                            node,
                            Trit::Unknown,
                            None,
                            &format!("trit-re:<{sha}> 样本身份（0 态：外部输入未测不可信）"),
                        )
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    report.samples += 1;
                    sample_of.insert(sha, node);
                }
                Some("judgment") => match JudgmentRow::from_json(&parsed) {
                    Some(row) => deferred.push((row.sha.clone(), row)),
                    None => report.bad_lines += 1,
                },
                _ => {}
            }
        }
    }

    // 按 (sha, id) 配对三源判定
    let mut paired: std::collections::BTreeMap<(String, String), Vec<JudgmentRow>> =
        std::collections::BTreeMap::new();
    for (sha, row) in deferred {
        paired.entry((sha, row.id.clone())).or_default().push(row);
    }

    // 隔离（外部输入自动检疫，与 intake_triage 同纪律）
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
                .quarantine(id, "外部逆向台账自动隔离（tmr-bridge 管线）")
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
    }

    // TMR 表决落账（按 key 稳定序——台账行可复算）
    for ((sha, id), rows) in paired {
        let votes: Vec<Trit> = rows.iter().filter_map(|r| vote_of(&r.value)).collect();
        let v_count = votes.iter().filter(|v| **v == Trit::Vulnerable).count();
        let u_count = votes.iter().filter(|v| **v == Trit::Unknown).count();
        let sample = match sample_of.get(&sha) {
            Some(s) => *s,
            None => {
                // 乱序防御：judgment 先于 file 行时样本节点按需立
                let node = journal
                    .spawn(parent, NodeKind::Message, &format!("trit-re 样本 {sha}"))
                    .map_err(|e| io::Error::other(e.to_string()))?;
                journal
                    .record(
                        node,
                        Trit::Unknown,
                        None,
                        &format!("trit-re:<{sha}> 样本身份（0 态：外部输入未测不可信）"),
                    )
                    .map_err(|e| io::Error::other(e.to_string()))?;
                report.samples += 1;
                sample_of.insert(sha.clone(), node);
                *sample_of.get(&sha).expect("刚插入")
            }
        };

        let verdict = if v_count >= 2 {
            report.corroborated += 1;
            Trit::Vulnerable // ≥2 源佐证：-1 成立
        } else if v_count == 1 {
            report.suppressed_single += 1;
            Trit::Unknown // 单源声称：降权为 0 + 注记（投毒抑制面）
        } else if u_count >= 1 {
            report.unknown += 1;
            Trit::Unknown // 全源没看见
        } else {
            continue; // 全源弃权（false）：不入账
        };

        let node = journal
            .spawn(sample, NodeKind::Message, &format!("trit-re 判定: {id}"))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let votes_note: Vec<String> = rows
            .iter()
            .map(|r| format!("{}={}", r.value, r.four))
            .collect();
        let conflicted = rows.iter().any(|r| r.four.eq_ignore_ascii_case("B"));
        if conflicted {
            report.conflicted += 1;
        }
        let note = format!(
            "trit-re:<{sha}> TMR{} v_count={v_count} 票=[{}]{}",
            if v_count >= 2 {
                " 佐证"
            } else {
                " 单源降权"
            },
            votes_note.join(" / "),
            if conflicted {
                " ⚠ four=B 矛盾告警"
            } else {
                ""
            },
        );
        journal
            .record(node, verdict, None, &note)
            .map_err(|e| io::Error::other(e.to_string()))?;
        report.findings += 1;
    }
    Ok(report)
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
        // four=B（Belnap 矛盾）= 扫描器内部证据自洽性告警——值映射照常
        //（B 判定的 value 是 unknown/true 由 trit-re 定），但**单独计数**：
        // 模因矛盾的机器可检测信号（MEMETIC-RESISTANCE 想法一）。
        if row.four.eq_ignore_ascii_case("B") {
            report.conflicted += 1;
        }
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

pub(crate) struct JudgmentRow {
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
    pub(crate) fn from_json(json: &Json) -> Option<Self> {
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
    fn four_b_counts_as_memetic_alarm() {
        // MEMETIC-RESISTANCE 想法一：four=B（Belnap 矛盾——扫描器内部证据
        // 自洽性告警，如"签过名但结构像加壳"）单独计数——模因矛盾的机器
        // 可检测信号；值映射照常（B 判定的 value 由 trit-re 定）。
        let (mut j, path) = temp_journal("memetic");
        let jsonl = concat!(
            r#"{"kind":"judgment","sha256":"deadb","id":"packed","title":"签名但结构像加壳","value":"unknown","four":"B","support":["authenticode.present"],"refute":["packer.section_name"],"unknown":[]}"#,
            "\n",
            r#"{"kind":"file","schema":3,"sha256":"deadb","size":7}"#,
            "\n",
            r#"{"kind":"judgment","sha256":"deadb","id":"injection","title":"注入","value":"true","four":"F","support":[],"refute":[],"unknown":[]}"#,
            "\n",
        );
        let report = intake_triage(&mut j, NodeId(0), jsonl, false).expect("入账");
        assert_eq!(report.conflicted, 1, "只有 four=B 计入矛盾告警");
        assert_eq!(report.vulnerable, 1, "F 判定照常 -1");
        assert_eq!(report.unknown, 1, "B 判定值映射照常（unknown → 0）");
        let dag = j.dag().clone();
        let packed_node = dag
            .nodes()
            .iter()
            .find(|n| n.title.contains("trit-re 判定: packed"))
            .expect("B 判定节点存在");
        assert!(
            packed_node
                .history
                .iter()
                .any(|e| e.note.contains("four=B") && e.note.contains("签名但结构像加壳")),
            "B 判定的 history 事件带 four 标记与原始 title"
        );
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
    #[test]
    #[test]
    fn tmr_bridge_corroborated_vs_suppressed() {
        // MEMETIC-RESISTANCE 想法三（管线形态）：三源 TMR 桥——
        // >=2 源一致 true → -1（佐证成立）；单源 true → 降级 0 + 注记。
        let (mut j, path) = temp_journal("tmr");
        let jrow = |sha: &str, value: &str, four: &str| {
            format!(
                r#"{{"kind":"judgment","sha256":"{sha}","id":"injection","title":"判定","value":"{value}","four":"{four}","support":[],"refute":[],"unknown":[]}}"#
            )
        };
        let s1 = "aa01";
        let s2 = "bb02";
        let j1 = format!("{}\n{}", jrow(s1, "true", "F"), jrow(s2, "true", "F"));
        let j2 = format!("{}\n{}", jrow(s1, "true", "F"), jrow(s2, "false", "F"));
        let j3 = format!("{}\n{}", jrow(s1, "true", "F"), jrow(s2, "false", "N"));
        let report = tmr_intake_triage(&mut j, NodeId(0), [&j1, &j2, &j3], false).expect("入账");
        assert_eq!(report.corroborated, 1, "s1 三源一致 true → 佐证成立");
        assert_eq!(
            report.suppressed_single, 1,
            "s2 单源 true → 降级（投毒抑制面）"
        );
        assert_eq!(report.findings, 2);
        let dag = j.dag().clone();
        let suppressed = dag
            .nodes()
            .iter()
            .find(|n| n.title.contains("injection") && n.verdict == Trit::Unknown)
            .expect("被降级的发现存在");
        assert!(
            suppressed
                .history
                .last()
                .expect("有事件")
                .note
                .contains("单源降权"),
            "降级注记可见"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tmr_bridge_counts_conflicted_and_skips_all_abstain() {
        let (mut j, path) = temp_journal("tmr2");
        let s1 = "cc03";
        // 全源 unknown → 0 态发现；一个源 four=B → 矛盾告警计数
        let jrow = |value: &str, four: &str| {
            format!(
                r#"{{"kind":"judgment","sha256":"{s1}","id":"packed","title":"判定","value":"{value}","four":"{four}","support":[],"refute":[],"unknown":[]}}"#
            )
        };
        let j1 = jrow("unknown", "B");
        let j2 = jrow("unknown", "N");
        let j3 = jrow("false", "N");
        let report = tmr_intake_triage(&mut j, NodeId(0), [&j1, &j2, &j3], false).expect("入账");
        assert_eq!(report.conflicted, 1, "four=B 矛盾告警计数（想法一联动）");
        assert_eq!(report.findings, 1, "unknown 落账为 0 态发现");
        // 全源 false → 不入账（扫描器永不 +1）
        let j4 = jrow("false", "F");
        let j5 = jrow("false", "F");
        let j6 = jrow("false", "F");
        let report = tmr_intake_triage(&mut j, NodeId(0), [&j4, &j5, &j6], false).expect("入账");
        assert_eq!(report.findings, 0, "全源弃权不入账");
        let _ = std::fs::remove_file(&path);
    }
}
