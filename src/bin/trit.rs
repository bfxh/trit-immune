//! `trit` 命令行：git 风格操作面——**journal 代替 git** 的入口。
//!
//! git 的每个核心操作在免疫账本上都有对应物（且大多更强）：
//!
//! | git | trit | 关系 |
//! |-----|------|------|
//! | `git init` | `trit init` | Journal::create（追加式日志即数据库） |
//! | `git log` | `trit log` | HLC 全序的 Delta 历史 |
//! | `git status` | `trit status` | 收敛度量 + 可疑队列 + 根门禁 |
//! | `git branch` | `trit branch` | spawn 分支节点（DAG 天生分叉） |
//! | `git commit` | `trit commit` | 记录裁决事件（新节点默认 0：未测不可信） |
//! | `git merge` | `trit merge` | merge_replicas（δ-CRDT：**无冲突合并**，与顺序无关） |
//! | `git checkout` | `trit checkout` | 重放到任意节点 = 时间旅行（日志不可变，历史永不丢） |
//! | `git clone` | `trit clone` | 复制 journal 文件（账本即工件） |
//!
//! 超出 git 的部分：`trit gate`（三值门禁——git 只知道冲突，不知道风险）、
//! `trit suspects`（0 态待办队列）。
//!
//! 默认账本：当前目录 `repo.tritj`（`-f` 可指定）。

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use trit_immune::{
    coords, delta, parse_stamped_line, retbridge, supply, Journal, NodeId, NodeKind, Trit,
};

const DEFAULT_LEDGER: &str = "repo.tritj";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Usage(msg)) => {
            eprintln!("用法错误：{msg}\n\n{}", help_text());
            ExitCode::from(2)
        }
        Err(CliError::Runtime(msg)) => {
            eprintln!("错误：{msg}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Runtime(String),
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Runtime(e.to_string())
    }
}

impl From<JournalErrorAlias> for CliError {
    fn from(e: JournalErrorAlias) -> Self {
        Self::Runtime(e.to_string())
    }
}

type JournalErrorAlias = trit_immune::JournalError;

fn run(args: &[String]) -> Result<(), CliError> {
    let Some(cmd) = args.first() else {
        return Err(CliError::Usage("缺命令".into()));
    };
    let rest = &args[1..];
    match cmd.as_str() {
        "init" => cmd_init(rest),
        "log" => cmd_log(rest),
        "status" => cmd_status(rest),
        "branch" => cmd_branch(rest),
        "commit" => cmd_commit(rest),
        "merge" => cmd_merge(rest),
        "checkout" => cmd_checkout(rest),
        "clone" => cmd_clone(rest),
        "gate" => cmd_gate(rest),
        "suspects" => cmd_suspects(rest),
        "catalog" => cmd_catalog(rest),
        "triage-bridge" => cmd_triage_bridge(rest),
        "sync-git" => cmd_sync_git(rest),
        "lock" => cmd_lock(rest),
        "help" | "--help" | "-h" => {
            println!("{}", help_text());
            Ok(())
        }
        other => Err(CliError::Usage(format!("未知命令 {other:?}"))),
    }
}

// ── 参数工具 ────────────────────────────────────────────────────────────

/// 从参数里取 `-f <file>`（默认 repo.tritj），返回剩余位置参数。
fn split_ledger(args: &[String]) -> (PathBuf, &[String]) {
    if args.len() >= 2 && args[0] == "-f" {
        (PathBuf::from(&args[1]), &args[2..])
    } else {
        (PathBuf::from(DEFAULT_LEDGER), args)
    }
}

/// **账本路径围栏**：解析后的路径必须落在当前工作目录或系统临时目录之内。
///
/// trit 是 git 风格的本地 CLI：账本属于「你当前所在的仓」。CLI 参数是外部
/// 输入，直通文件读写就是一条 path-traversal 污点链——敲错路径会改掉任意
/// 文件。围栏做两件事：`canonicalize` 消解 `..` 与符号形态，然后要求结果
/// 以 cwd 或 temp（已 canonical 化）为前缀；两者之外一律拒绝。
/// temp 白名单是给「一次性/测试账本」的显式豁免（那是用户自己的临时目录，
/// 风险面 = 用户自己的文件），常态使用全部收在 cwd 内。
fn fence_ledger_path(raw: &std::path::Path) -> Result<PathBuf, CliError> {
    let cwd = std::env::current_dir()
        .map_err(|e| CliError::Runtime(format!("取当前目录失败：{e}")))?
        .canonicalize()
        .map_err(|e| CliError::Runtime(format!("解析当前目录失败：{e}")))?;
    let candidate = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };
    let canonical = match candidate.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            // 文件（或中间目录）尚不存在（init 允许一次建多层）：向上找最近的
            // 真实存在祖先做 canonicalize——`..` 组分在这一步被消解——再把
            // 中间不存在的组件原样拼回去。拼回去的部分不再含 `..`：含 `..`
            // 的路径段必经祖先 canonicalize，逃逸由最后的 starts_with 拦。
            let mut base = candidate.clone();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            while !(base.is_dir() || base.is_file()) {
                match (base.parent(), base.file_name()) {
                    (Some(parent), Some(name)) => {
                        tail.push(name.to_os_string());
                        base = parent.to_path_buf();
                    }
                    _ => break,
                }
            }
            let resolved = base
                .canonicalize()
                .map_err(|e| CliError::Runtime(format!("解析路径 {} 失败：{e}", base.display())))?;
            tail.iter().rev().fold(resolved, |acc, part| acc.join(part))
        }
    };
    let temp = std::env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir());
    if !canonical.starts_with(&cwd) && !canonical.starts_with(&temp) {
        return Err(CliError::Runtime(format!(
            "账本路径 {} 在当前工作目录 {} 与临时目录之外——trit 只操作本仓账本",
            canonical.display(),
            cwd.display()
        )));
    }
    Ok(canonical)
}

fn open_ledger(args: &[String]) -> Result<(Journal, PathBuf), CliError> {
    let (path, _) = split_ledger(args);
    let path = fence_ledger_path(&path)?;
    let j = Journal::open_as(&path, 0)
        .map_err(|e| CliError::Runtime(format!("打开账本 {} 失败：{e}", path.display())))?;
    Ok((j, path))
}

// ── 命令 ────────────────────────────────────────────────────────────────

/// `trit init <dir> [title]`：在目录下建新账本（`<dir>/repo.tritj`）。
fn cmd_init(args: &[String]) -> Result<(), CliError> {
    let dir = args
        .first()
        .ok_or_else(|| CliError::Usage("init 需要 <dir>".into()))?;
    let title = args.get(1).cloned().unwrap_or_else(|| "main".into());
    let path = fence_ledger_path(&PathBuf::from(dir).join(DEFAULT_LEDGER))?;
    if path.exists() {
        return Err(CliError::Runtime(format!("{} 已存在", path.display())));
    }
    // `trit init ./new-repo` 应当像 git init 一样把目录一起建出来：
    // 少这一步时 Journal::create 只会抛 os error 3（路径不存在），用户看不出是 init 的锅。
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::Runtime(format!("创建账本目录 {} 失败：{e}", parent.display()))
        })?;
    }
    Journal::create_as(&path, &title, 0)?;
    println!("初始化账本 {}（根：{title}）", path.display());
    Ok(())
}

/// `trit log [-n N] [-f file]`：HLC 全序的 Delta 历史。
fn cmd_log(args: &[String]) -> Result<(), CliError> {
    // 独立扫描：-n 与 -f 任意顺序
    let mut limit = usize::MAX;
    let mut path = PathBuf::from(DEFAULT_LEDGER);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                limit = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(usize::MAX);
                i += 2;
            }
            "-f" => {
                if let Some(p) = args.get(i + 1) {
                    path = PathBuf::from(p);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    let path = fence_ledger_path(&path)?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| CliError::Runtime(format!("读账本失败：{e}")))?;
    let mut shown = 0usize;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue; // 头部
        }
        if line.trim().is_empty() {
            continue;
        }
        if shown >= limit {
            break;
        }
        let Ok((ts, d)) = parse_stamped_line(line) else {
            println!("{:4}: <坏行如实展示> {line}", i);
            continue;
        };
        println!("{:4} {} {}", i, ts, delta::encode(&d));
        shown += 1;
    }
    Ok(())
}

/// `trit status [-f file]`：收敛度量 + 根门禁 + 节点数。
fn cmd_status(args: &[String]) -> Result<(), CliError> {
    let (j, path) = open_ledger(args)?;
    let dag = j.dag().clone();
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    let conv = dag.convergence();
    let root_gate = dag.merge_gate(NodeId((dag.nodes().len() - 1) as u32));
    println!("账本：{}", path.display());
    println!(
        "节点：{}（+{} / 0:{} / -{} / 隔离 {}）",
        conv.total, conv.hardened, conv.unknown, conv.vulnerable, conv.quarantined
    );
    println!("收敛率：{:.3}", conv.ratio);
    println!("尾门禁：{root_gate:?}");
    let suspects = dag.suspects();
    println!("可疑队列：{} 个", suspects.len());
    Ok(())
}

/// `trit branch <name> [-f file]`：spawn 分支节点（DAG 天生分叉，无 HEAD 概念——
/// 每个分支就是一个节点，工作目标用节点号寻址）。
fn cmd_branch(args: &[String]) -> Result<(), CliError> {
    let (name, ledger_args) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("branch 需要 <name>".into()))?;
    let (mut j, path) = open_ledger(ledger_args)?;
    let parent = NodeId((j.dag().nodes().len() - 1) as u32);
    let id = j.spawn(parent, NodeKind::Delta, &format!("branch:{name}"))?;
    let n = id.0;
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    println!("分支 {name} = 节点 #{n:02}（账本 {}）", path.display());
    Ok(())
}

/// `trit commit -m <note> [-v -1|0|+1] [-n <node>] [-f file]`：
/// 记录裁决事件。默认 0 态（未测不可信）；`-n` 缺省 = 最新节点。
fn cmd_commit(args: &[String]) -> Result<(), CliError> {
    let mut note: Option<String> = None;
    let mut verdict = Trit::Unknown;
    let mut node: Option<u32> = None;
    let mut ledger_args: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" => {
                note = args.get(i + 1).cloned();
                i += 2;
            }
            "-v" => {
                let v = args
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("-v 需要 -1|0|+1".into()))?;
                verdict = v
                    .parse()
                    .map_err(|_| CliError::Usage(format!("非法裁决 {v:?}（-1|0|+1）")))?;
                i += 2;
            }
            "-n" => {
                let n = args
                    .get(i + 1)
                    .ok_or_else(|| CliError::Usage("-n 需要节点号".into()))?;
                node = Some(
                    n.parse()
                        .map_err(|_| CliError::Usage(format!("节点号非数字：{n:?}")))?,
                );
                i += 2;
            }
            other => {
                ledger_args.push(other.to_string());
                i += 1;
            }
        }
    }
    let note = note.ok_or_else(|| CliError::Usage("commit 需要 -m <note>".into()))?;
    let (mut j, path) = open_ledger(&ledger_args)?;
    let target = match node {
        Some(n) => NodeId(n),
        None => NodeId((j.dag().nodes().len() - 1) as u32),
    };
    if target.0 as usize >= j.dag().nodes().len() {
        return Err(CliError::Runtime(format!("节点 #{:02} 不存在", target.0)));
    }
    j.record(target, verdict, None, &note)?;
    let n = target.0;
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    println!("记录 {n:02} ← {verdict}（{}）", path.display());
    Ok(())
}

/// `trit merge <other> [-f file]`：δ-CRDT 合并——HLC 戳去重、全序归并、
/// **与输入顺序无关、无冲突**（这是比 git merge 强的地方：没有冲突标记，
/// 只有收敛）。
fn cmd_merge(args: &[String]) -> Result<(), CliError> {
    let (other, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("merge 需要 <other 账本>".into()))?;
    let (mut local, path) = open_ledger(rest)?;
    let other_path = fence_ledger_path(&PathBuf::from(other))?;
    if !other_path.is_file() {
        return Err(CliError::Runtime(format!(
            "{} 不是文件",
            other_path.display()
        )));
    }
    // 读入对方日志（跳过头部），以写者 id=1 的身份参与合并
    let text = std::fs::read_to_string(&other_path)
        .map_err(|e| CliError::Runtime(format!("读 {} 失败：{e}", other_path.display())))?;
    let mut remote: Vec<trit_immune::Stamped> = Vec::new();
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        let (ts, d) = parse_stamped_line(line)
            .map_err(|e| CliError::Runtime(format!("{} 坏行：{e}", other_path.display())))?;
        remote.push(trit_immune::Stamped { ts, delta: d });
    }
    let local_stream: Vec<trit_immune::Stamped> = {
        let ltext = std::fs::read_to_string(&path)
            .map_err(|e| CliError::Runtime(format!("读 {} 失败：{e}", path.display())))?;
        ltext
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .map(|l| parse_stamped_line(l).map(|(ts, d)| trit_immune::Stamped { ts, delta: d }))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CliError::Runtime)?
    };
    let outcome = trit_immune::merge_replicas(vec![(0, local_stream), (1, remote)]);
    if !outcome.deferred.is_empty() {
        return Err(CliError::Runtime(format!(
            "{} 条增量进隔离区（重放失败，见 journal 文档）",
            outcome.deferred.len()
        )));
    }
    local.adopt(outcome.canonical)?;
    println!(
        "合并完成：{} 节点（收敛自两份账本，与顺序无关）",
        local.dag().nodes().len()
    );
    Ok(())
}

/// `trit checkout <node> [-f file]`：**时间旅行**——重放到节点 N 时的全图
/// 状态（只读视图；日志不可变，历史永不丢，这正是账本代替 git 的底气）。
fn cmd_checkout(args: &[String]) -> Result<(), CliError> {
    let (n, ledger_args) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("checkout 需要 <node>".into()))?;
    let n: u32 = n
        .parse()
        .map_err(|_| CliError::Usage(format!("节点号非数字：{n:?}")))?;
    let (j, _) = open_ledger(ledger_args)?;
    let dag = j.dag().clone();
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    if n as usize >= dag.nodes().len() {
        return Err(CliError::Runtime(format!("节点 #{n:02} 不存在")));
    }
    // 重放：只保留 n0..=n（含父链闭包），打印时间旅行视图
    let mut view = trit_immune::ImmuneDag::root("时间旅行视图");
    for node in &dag.nodes()[..=n as usize] {
        let kind = node.kind;
        let parent = node
            .parent
            .map(|p| NodeId(p.0.min(view.nodes().len() as u32 - 1)))
            .unwrap_or(NodeId(0));
        let id = view.spawn(parent, kind, &node.title);
        if node.quarantined {
            view.quarantine(id, "checkout：保留隔离标记");
        }
        for e in &node.history {
            view.record(id, e.verdict, None, &e.note);
        }
    }
    println!("节点 #{n:02} 时的全图（{} 节点）：", view.nodes().len());
    print!("{}", view.render());
    Ok(())
}

/// `trit clone <src> <dst>`：账本即工件——复制文件即克隆（含全部历史）。
fn cmd_clone(args: &[String]) -> Result<(), CliError> {
    let (src, dst) = args
        .split_first()
        .and_then(|(s, r)| r.first().map(|d| (s, d)))
        .ok_or_else(|| CliError::Usage("clone 需要 <src> <dst>".into()))?;
    let src = fence_ledger_path(std::path::Path::new(src))?;
    let dst = fence_ledger_path(std::path::Path::new(dst))?;
    std::fs::copy(&src, &dst).map_err(|e| CliError::Runtime(format!("克隆失败：{e}")))?;
    println!(
        "克隆 {} → {}（含全部历史，追加式日志天然完整）",
        src.display(),
        dst.display()
    );
    Ok(())
}

/// `trit gate [-n <node>] [-f file]`：三值门禁——git 只知道冲突，这里知道风险。
fn cmd_gate(args: &[String]) -> Result<(), CliError> {
    let (j, _) = open_ledger(args)?;
    let dag = j.dag().clone();
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    let tip = NodeId((dag.nodes().len() - 1) as u32);
    let gate = dag.merge_gate(tip);
    let breaches = dag.breach_sources(tip);
    println!("尾节点 #{:02} 门禁：{gate:?}", tip.0);
    if breaches.is_empty() {
        println!("无打穿来源");
    } else {
        println!("打穿来源：");
        for (id, kind) in breaches {
            println!("  #{:02}（{:?}）", id.0, kind);
        }
    }
    Ok(())
}

/// `trit suspects [-f file]`：0 态待办队列（未测即不可信的名单）。
fn cmd_suspects(args: &[String]) -> Result<(), CliError> {
    let (j, _) = open_ledger(args)?;
    let dag = j.dag().clone();
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    let suspects = dag.suspects();
    println!("可疑队列 {} 个：", suspects.len());
    for id in suspects {
        let n = dag.node(id);
        println!("  #{:02} {}", id.0, n.title);
    }
    Ok(())
}

/// `trit triage-bridge <JSONL> [-f file] [-n <parent>] [--no-quarantine]`：
/// **trit-re 台账桥**（ROADMAP #51）——逆向发现吃进裁决账本。
/// 三值对齐：true → -1、unknown → 0、false 不入账（扫描器永不 +1）；
/// 外部输入自动隔离（`--no-quarantine` 解除）；JSONL 缺省读 stdin（`-`）。
fn cmd_triage_bridge(args: &[String]) -> Result<(), CliError> {
    let mut path = PathBuf::from(DEFAULT_LEDGER);
    let mut parent: u32 = 0;
    let mut quarantine = true;
    let mut source: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-f" => {
                path = PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::Usage("-f 需要跟一个文件".into()))?,
                );
                i += 2;
            }
            "-n" => {
                parent = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| CliError::Usage("-n 需要节点号".into()))?;
                i += 2;
            }
            "--no-quarantine" => {
                quarantine = false;
                i += 1;
            }
            "-" => {
                source = Some("-".into());
                i += 1;
            }
            other if other.starts_with('-') => i += 1,
            other => {
                if source.is_none() {
                    source = Some(other.to_string());
                }
                i += 1;
            }
        }
    }
    let source = source.unwrap_or_else(|| "-".into());
    let jsonl = if source == "-" {
        let mut buffer = String::new();
        io::Read::read_to_string(&mut io::stdin(), &mut buffer)
            .map_err(|e| CliError::Runtime(format!("读 stdin 失败：{e}")))?;
        buffer
    } else {
        let file = fence_ledger_path(std::path::Path::new(&source))?;
        std::fs::read_to_string(&file)
            .map_err(|e| CliError::Runtime(format!("读 {} 失败：{e}", file.display())))?
    };
    // `-f` 本命令独立解析（位置参数在前时 open_ledger 的 split_ledger 认不到）
    let ledger_path = fence_ledger_path(&path)?;
    let mut j = Journal::open_as(&ledger_path, 0)
        .map_err(|e| CliError::Runtime(format!("打开账本 {} 失败：{e}", ledger_path.display())))?;
    let parent = NodeId(parent);
    if parent.0 as usize >= j.dag().nodes().len() {
        return Err(CliError::Runtime(format!("父节点 #{:02} 不存在", parent.0)));
    }
    let report = retbridge::intake_triage(&mut j, parent, &jsonl, quarantine)
        .map_err(|e| CliError::Runtime(e.to_string()))?;
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    println!(
        "台账桥：样本 {}，发现 {}（-1 {} / 0 {}），False 不入账 {}，坏行 {}，隔离 {} → {}",
        report.samples,
        report.findings,
        report.vulnerable,
        report.unknown,
        report.skipped_false,
        report.bad_lines,
        report.quarantined,
        ledger_path.display()
    );
    Ok(())
}

/// `trit catalog [-f file]`：**发现目录**——大规模产出的治理视图
/// （openai/math 管道的账本对应物：族折叠 / 验证层级 / 修正注记）。
/// 输出统计 + 族清单（签名序）+ 修正注记；目录是账本的纯视图，
/// 只读不改账。
fn cmd_catalog(args: &[String]) -> Result<(), CliError> {
    let (j, _) = open_ledger(args)?;
    let dag = j.dag().clone();
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    let cat = trit_immune::catalog(&dag);
    let st = &cat.stats;
    println!(
        "发现 {} 条 / {} 族（已验证 {:.1}%：复现 {} + 已裁定 {}，纯声称 {}，矛盾 {}）",
        st.findings,
        st.families,
        st.verified_ratio * 100.0,
        st.reproduced,
        st.adjudicated,
        st.claimed,
        st.contradictions
    );
    for f in &cat.families {
        println!(
            "  族「{}」{} {} 成员，代表 #{:02}：{}",
            f.signature,
            match f.verdict {
                trit_immune::Trit::Vulnerable => "-1",
                trit_immune::Trit::Unknown => "0",
                trit_immune::Trit::Hardened => "+1",
            },
            f.members.len(),
            f.representative.0,
            dag.node(f.representative).title,
        );
    }
    if !cat.corrections.is_empty() {
        println!("修正注记（旧裁决保留在账本，永不删除）：");
        for c in &cat.corrections {
            let label = match c.kind {
                trit_immune::CorrectionKind::Fixed => "已修复",
                trit_immune::CorrectionKind::Refuted => "声明被证伪",
                trit_immune::CorrectionKind::Contradicted => "反复修正，待人",
            };
            println!("  #{:02} {}：{}", c.node.0, label, dag.node(c.node).title);
        }
    }
    Ok(())
}

/// `trit sync-git <repo> [-f file] [--open]`：**git 共存桥**——git 继续管
/// 代码文件（内容寻址、生态工具），账本把 git 提交历史吸收进来参与裁决。
/// 每条 commit 立一个 Message 节点：**0 态入账**（作者声称≠已验证），
/// 默认整批隔离（外部导入防污染协议；`--open` 解除隔离等人逐条放行）。
/// 返回账本后，扫描器/红队/门禁就可以指着这些节点干活。
fn cmd_sync_git(args: &[String]) -> Result<(), CliError> {
    let mut quarantine = true;
    let mut rest: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--open" => quarantine = false,
            other => rest.push(other.to_string()),
        }
    }
    let (repo, ledger_args) = rest
        .split_first()
        .ok_or_else(|| CliError::Usage("sync-git 需要 <repo 路径>".into()))?;
    let repo_path = PathBuf::from(repo);
    let (mut j, path) = open_ledger(ledger_args)?;
    let commits = trit_immune::collect_git_log(&repo_path)
        .map_err(|e| CliError::Runtime(format!("读 git 历史失败：{e}")))?;
    let parent = NodeId((j.dag().nodes().len() - 1) as u32);
    let n = trit_immune::import_commits(&mut j, parent, &commits, quarantine)?;
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    println!(
        "导入 {} 条提交 → {} 个 0 态节点（隔离={}，账本 {}）",
        commits.len(),
        n,
        quarantine,
        path.display()
    );
    Ok(())
}

/// `trit lock [-f file] [--build <feature,feature>]`：**依赖坐标入账**，
/// **Cargo.lock 从 stdin 读入**（管线式 `cargo generate-lockfile | trit lock`）
/// ——外部文件内容不经 CLI 路径参数，path-traversal 面从入口消失
/// （ROADMAP #49 出口面的第五轮修复：引擎认不出围栏形状，就移除污点路径本身）。
///
/// 把本项目锁文件里实际解析到的每个依赖，立成账本中的坐标节点（**0 态**——
/// 外部事实入账，未验证不算安全），并连一条"消费 → 本仓根"的边，让库被打穿时
/// 本仓的门禁与有效裁决直接看见。`Cargo.lock` 不记 feature 集；要把同 checksum
/// 不同 feature 的产物分开，用 `--build` 内联清单（逗号分隔 feature 名）。
/// **自由文本不进账本**：字符集闸（字母数字 `_ - . +`）+ delta 转义双消毒。
/// 幂等：同坐标再跑不重复建节点。
fn cmd_lock(args: &[String]) -> Result<(), CliError> {
    let mut text = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut text)
        .map_err(|e| CliError::Runtime(format!("读 stdin 失败：{e}")))?;
    lock_from(args, &text)
}

/// lock 的实现体（stdin 文本由 [`cmd_lock`] 注入，测试可直接喂）。
fn lock_from(args: &[String], lock_text: &str) -> Result<(), CliError> {
    // 参数惯例与 merge / sync-git 一致：`-f` 在前后都要认。
    let mut path = PathBuf::from(DEFAULT_LEDGER);
    let mut build: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-f" => {
                path = PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::Usage("-f 需要跟一个文件".into()))?,
                );
                i += 2;
            }
            "--build" => {
                build = Some(
                    args.get(i + 1)
                        .ok_or_else(|| CliError::Usage("--build 需要跟 feature 清单".into()))?
                        .clone(),
                );
                i += 2;
            }
            _ => i += 1,
        }
    }
    // 指纹写进账本行：逗号/空白分隔的 feature 名，只放行 feature 名字符，
    // 其余一律拒绝——自由文本不进账本（字符集闸 + delta 转义双消毒）。
    let build = build
        .map(|raw| -> Result<String, CliError> {
            let fingerprint = raw
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if fingerprint.is_empty()
                || !fingerprint
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ',' | '.' | '+'))
            {
                return Err(CliError::Usage(format!(
                    "--build 的 feature 清单只接受 feature 名字符（字母数字 _ - . +，逗号分隔），收到：{fingerprint}"
                )));
            }
            Ok(fingerprint)
        })
        .transpose()?;
    let path = fence_ledger_path(&path)?;
    let mut j = Journal::open_as(&path, 0)
        .map_err(|e| CliError::Runtime(format!("打开账本 {} 失败：{e}", path.display())))?;
    let pins = supply::parse_lock(lock_text);
    let report = coords::attach_pins(&mut j, &pins, build.as_deref())
        .map_err(|e| CliError::Runtime(format!("坐标入账失败：{e}")))?;
    println!(
        "坐标入账 {} 条：新建 {}，复用 {}（账本 {}）",
        report.all.len(),
        report.created.len(),
        report.reused,
        path.display()
    );
    for (n, c) in &report.created {
        println!("  #{:02} {}", n.0, c.key());
    }
    drop(j.into_dag().map_err(|e| CliError::Runtime(e.to_string()))?);
    Ok(())
}

fn help_text() -> String {
    "trit —— journal 代替 git 的命令行（三进制免疫账本）

命令：
  init <dir> [title]        建新账本（<dir>/repo.tritj）
  log [-n N] [-f file]      HLC 全序 Delta 历史
  status [-f file]          收敛度量 + 尾门禁 + 可疑数
  branch <name> [-f file]   spawn 分支节点（DAG 天生分叉）
  commit -m <note> [-v -1|0|+1] [-n <node>] [-f file]
                            记录裁决事件（默认 0：未测不可信）
  merge <other> [-f file]   δ-CRDT 合并（无冲突，与顺序无关）
  checkout <node> [-f file] 时间旅行：重放到节点 N 的全图状态
  clone <src> <dst>         账本即工件，复制即克隆
  gate [-n node] [-f file]  三值门禁 + 打穿来源
  suspects [-f file]        0 态待办队列
  catalog [-f file]         发现目录：族折叠 + 验证层级 + 修正注记（只读）
  triage-bridge <JSONL|-> [-f file] [-n N] [--no-quarantine]
                            trit-re 台账桥：逆向发现吃进裁决账本
  sync-git <repo> [-f file] [--open]
                            git 共存桥：提交历史吸收进账本（0 态+默认隔离）
  lock [-f file] [--build <feature,feature>]
                            依赖坐标入账（Cargo.lock 从 stdin 读，幂等）
  help                      本帮助

默认账本：当前目录 repo.tritj（-f 可指定）。"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trit-cli-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn s(v: impl Into<String>) -> String {
        v.into()
    }

    #[test]
    fn fence_confines_ledger_paths_to_cwd_and_temp() {
        // cwd 内的相对路径放行（解析为 cwd 下的规范形）。
        let inside = fence_ledger_path(std::path::Path::new("fence-check.tritj")).unwrap();
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(inside.starts_with(&cwd), "{inside:?} 应在 cwd {cwd:?} 内");
        // 临时目录白名单放行（测试与一次性账本的显式豁免）。
        let temp_file = tmpdir("fence-temp").join("ledger.tritj");
        assert!(fence_ledger_path(&temp_file).is_ok());
        // `..` 逃出 cwd 被拒。
        let escape = fence_ledger_path(std::path::Path::new("../fence-escape.tritj"));
        assert!(matches!(escape, Err(CliError::Runtime(_))), "{escape:?}");
        // cwd 之外的绝对路径被拒（用 cwd 的兄弟目录构造一个稳定反例）。
        let sibling = cwd
            .parent()
            .map(|p| p.join("definitely-outside-fence.tritj"))
            .unwrap_or_else(|| std::path::PathBuf::from("Z:\\definitely-outside.tritj"));
        assert!(matches!(
            fence_ledger_path(&sibling),
            Err(CliError::Runtime(_))
        ));
    }

    #[test]
    fn run_refuses_ledger_paths_outside_fence() {
        // CLI 层面：-f 指到 cwd/temp 之外 ⇒ Runtime 错误，而不是去改那个文件。
        let outside = std::env::current_dir()
            .unwrap()
            .parent()
            .map(|p| p.join("outside-fence.tritj"))
            .unwrap_or_else(|| std::path::PathBuf::from("Z:\\outside.tritj"));
        let outcome = run(&[s("log"), s("-f"), s(outside.to_string_lossy().to_string())]);
        assert!(matches!(outcome, Err(CliError::Runtime(_))), "{outcome:?}");
    }

    #[test]
    fn init_creates_missing_directories_and_refuses_overwrite() {
        let base = tmpdir("init-missing");
        let target = base.join("nested").join("brand-new");

        run(&[s("init"), s(target.to_string_lossy().to_string())])
            .expect("init 应能把不存在的父目录一起建出来");
        assert!(
            target.join(DEFAULT_LEDGER).is_file(),
            "init 后账本文件必须存在"
        );

        let again = run(&[s("init"), s(target.to_string_lossy().to_string())]);
        assert!(
            matches!(again, Err(CliError::Runtime(_))),
            "重复 init 不该静默覆盖已有账本：{again:?}"
        );
    }

    #[test]
    fn full_git_style_workflow() {
        let dir = tmpdir("wf");
        let ledger = dir.join(DEFAULT_LEDGER);

        // init → branch → commit(0 默认) → commit(+1) → status → gate → checkout
        run(&[s("init"), s(dir.to_string_lossy().to_string())]).unwrap();
        assert!(ledger.is_file(), "init 应产生账本");

        run(&[
            s("branch"),
            s("feat-login"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[
            s("commit"),
            s("-m"),
            s("登录模块完成"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[
            s("commit"),
            s("-m"),
            s("回归通过"),
            s("-v"),
            s("+1"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();

        // status 与 gate 不炸且输出非空（走 std::io 捕获太重，只验证 Ok）
        run(&[
            s("status"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[s("gate"), s("-f"), s(ledger.to_string_lossy().to_string())]).unwrap();
        run(&[
            s("suspects"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[
            s("checkout"),
            s("1"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[
            s("log"),
            s("-n"),
            s("3"),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();

        // clone：副本内容一致
        let dst = dir.join("clone.tritj");
        run(&[
            s("clone"),
            s(ledger.to_string_lossy().to_string()),
            s(dst.to_string_lossy().to_string()),
        ])
        .unwrap();
        assert_eq!(
            fs::read_to_string(&ledger).unwrap(),
            fs::read_to_string(&dst).unwrap(),
            "克隆应逐字节一致"
        );

        // merge：克隆侧追加再合回（δ-CRDT 无冲突）
        run(&[
            s("commit"),
            s("-m"),
            s("克隆侧增量"),
            s("-v"),
            s("+1"),
            s("-f"),
            s(dst.to_string_lossy().to_string()),
        ])
        .unwrap();
        run(&[
            s("merge"),
            s(dst.to_string_lossy().to_string()),
            s("-f"),
            s(ledger.to_string_lossy().to_string()),
        ])
        .unwrap();

        // 合并后主账本应含克隆侧增量（Record 不增节点数，追加进 #1 的历史）
        let j = Journal::open_as(&ledger, 0).unwrap();
        let n1 = j.dag().node(NodeId(1));
        assert!(
            n1.history.iter().any(|e| e.note.contains("克隆侧增量")),
            "δ-CRDT 合并应把克隆侧裁决带进来：{:?}",
            n1.history
        );
        drop(j.into_dag().unwrap());

        // sync-git：非 git 目录在 spawn 之前被拒（错误路径，零进程创建）
        let missing = dir.join("not-a-repo");
        assert!(matches!(
            run(&[s("sync-git"), s(missing.to_string_lossy().to_string())]),
            Err(CliError::Runtime(_))
        ));

        // 用法错误路径
        assert!(matches!(
            run(&[s("commit"), s("-m")]),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(run(&[s("nope")]), Err(CliError::Usage(_))));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_reads_cargo_lock_from_stdin() {
        // 新口径 `lock [-f file] [--build features]`：Cargo.lock 从 stdin 读入
        //（path-traversal 面从入口消失）；`-f` 排在参数任意位置都必须生效，
        // 否则坐标静默写进默认账本——同一命令行写到了另一个文件。
        let dir = tmpdir("lock-opt");
        run(&[s("init"), s(dir.to_string_lossy().to_string())]).unwrap();
        let ledger = dir.join(DEFAULT_LEDGER);
        let lock_text =
            "[[package]]\nname = \"shared-lib\"\nversion = \"1.2.0\"\nchecksum = \"aaa\"\n";

        lock_from(
            &[s("lock"), s("-f"), s(ledger.to_string_lossy().to_string())],
            lock_text,
        )
        .expect("lock 应接受 -f（Cargo.lock 走 stdin）");

        // --build 内联清单：字符集闸放行合法名，拒绝非法字符
        lock_from(
            &[
                s("lock"),
                s("-f"),
                s(ledger.to_string_lossy().to_string()),
                s("--build"),
                s("serde_json,git2"),
            ],
            lock_text,
        )
        .expect("合法 feature 清单");
        assert!(
            matches!(
                lock_from(
                    &[
                        s("lock"),
                        s("-f"),
                        s(ledger.to_string_lossy().to_string()),
                        s("--build"),
                        s("a;b")
                    ],
                    lock_text
                ),
                Err(CliError::Usage(_))
            ),
            "分号不在 feature 名字符集内——自由文本不进账本"
        );

        let j = Journal::open_as(&ledger, 0).unwrap();
        let titles: Vec<String> = j
            .dag()
            .nodes()
            .iter()
            .filter(|n| n.title.starts_with("COORD "))
            .map(|n| n.title.clone())
            .collect();
        assert_eq!(
            titles.len(),
            2,
            "无 build 与 --build=serde_json,git2 是两个坐标（逐字段相等才同坐标，by design）；非法字符集调用没建任何节点：{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.ends_with("|-")),
            "无 build 坐标在案"
        );
        assert!(
            titles.iter().any(|t| t.ends_with("serde_json,git2")),
            "带 build 坐标在案"
        );
        drop(j.into_dag().unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }
}
