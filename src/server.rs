//! 本地 HTTP 服务器：把免疫网络暴露成服务（std 线程 + RwLock，零依赖）。
//!
//! 并发模型（"AI 高频操作"的答案在架构上）：
//! - **读多写少**：render/gate/suspects 走读锁并行；deltas（合并采纳）与
//!   scan（校准入账）走写锁串行——单写者纪律在服务边界的体现；
//! - **高频多写者**不在一个 journal 上抢锁，而是各开副本（各自写者 id）、
//!   经 `/v1/deltas` 反熵合并——合并内核与输入顺序无关（有测试钉死）；
//! - 安全边界：服务默认绑 127.0.0.1（监听 ≠ 出网请求）；本服务自身不发起
//!   URL 请求；任何未来出网一律走 [`crate::net::check_url`]。

use crate::design::{self, DesignArea, PrIntake};
use crate::diag::{self, Diagnostic, Severity};
#[cfg(test)]
use crate::fleet::Fleet;
use crate::journal::Journal;
use crate::lsp;
use crate::scan;
use crate::sync::{self, LogFrame};
use crate::taskmd;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 16 * 1024 * 1024;

/// 共享的免疫网络服务。
#[derive(Debug, Clone)]
pub struct Server {
    pub journal: Arc<RwLock<Journal>>,
}

impl Server {
    pub fn new(journal: Journal) -> Self {
        Self {
            journal: Arc::new(RwLock::new(journal)),
        }
    }

    pub fn from_shared(journal: Arc<RwLock<Journal>>) -> Self {
        Self { journal }
    }

    /// 阻塞服务循环（每连接一线程，读多写少）。返回实际绑定地址。
    pub fn serve(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let bound = listener.local_addr()?;
        let shared = Arc::clone(&self.journal);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    let _ = handle_conn(&mut stream, &shared);
                });
            }
        });
        Ok(bound)
    }

    /// TLS 直连形态（`tls` feature）：每连接先握手再进同一个连接循环。
    /// 语义与 [`serve`] 逐字一致——**只有传输层换了，路由/账本/纪律全同**。
    /// 证书生产用 CA 签发；测试用 `tls::generate_self_signed`（见 [`crate::tls`]）。
    #[cfg(feature = "tls")]
    pub fn serve_tls(
        &self,
        addr: SocketAddr,
        config: rustls::ServerConfig,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let bound = listener.local_addr()?;
        let config = Arc::new(config);
        let shared = Arc::clone(&self.journal);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(sock) = stream else { continue };
                let shared = Arc::clone(&shared);
                let config = Arc::clone(&config);
                std::thread::spawn(move || {
                    // 明文客户端连进来会在握手处失败——如实丢弃，不当 HTTP 处理
                    let Ok(mut tls) = crate::tls::accept(&config, sock) else {
                        return;
                    };
                    let _ = handle_conn(&mut tls, &shared);
                    // 优雅关闭：TLS 要求 close_notify，裸 EOF 会被对端 rustls 客户端
                    // 当协议错误（UnexpectedEof）——与明文版"写完即关"在这里分叉
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        Ok(bound)
    }
}

fn handle_conn<S: std::io::Read + std::io::Write>(
    stream: &mut S,
    journal: &RwLock<Journal>,
) -> io::Result<()> {
    let (method, path, query, body) = read_request(stream)?;
    let (status, text) = route(journal, &method, &path, &query, &body);
    let resp = format_response(status, &text);
    stream.write_all(resp.as_bytes())
}

/// 检查类层落账（diag/lsp 共用同一语义与同一响应形状）：
/// 任一 error → 层 `-1`；否则任一 warning → `0`；干净 → `+1`（检查的通过是权威结论）。
fn record_check_layer(
    journal: &RwLock<Journal>,
    node: u32,
    layer: &str,
    diags: &[Diagnostic],
) -> (u16, String) {
    let verdict = diag::layer_verdict(diags);
    let errors = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warnings = diags
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let len = journal.read().expect("锁中毒").dag().nodes().len() as u32;
    if node >= len {
        return (404, format!("节点 #{node:02} 不存在\n"));
    }
    let applied = {
        let mut j = journal.write().expect("锁中毒");
        j.append_delta(&crate::Delta::Record {
            id: crate::NodeId(node),
            verdict,
            evidence: None,
            note: format!("{layer}：errors={errors} warnings={warnings}（检查类，可为 +1）"),
        })
    };
    match applied {
        Ok(()) => (
            200,
            format!(
                "diagnostics={} errors={} warnings={} layer={verdict} check_may_plus1=true\n",
                diags.len(),
                errors,
                warnings
            ),
        ),
        Err(e) => (500, format!("写入失败：{e}\n")),
    }
}

fn route(
    journal: &RwLock<Journal>,
    method: &str,
    path: &str,
    query: &[(String, String)],
    body: &str,
) -> (u16, String) {
    match (method, path) {
        ("GET", "/v1/health") => (200, "ok\n".into()),
        ("GET", "/v1/render") => (200, journal.read().expect("锁中毒").dag().render()),
        ("GET", "/v1/suspects") => {
            let j = journal.read().expect("锁中毒");
            let list: Vec<String> = j
                .dag()
                .suspects()
                .iter()
                .map(|id| format!("#{:02} {}", id.0, j.dag().node(*id).title))
                .collect();
            (200, format!("{}\n", list.join("\n")))
        }
        ("GET", "/v1/taskbar") => {
            let Some((_, v)) = query.iter().find(|(k, _)| k == "parent") else {
                return (400, "缺 parent 参数\n".into());
            };
            let Ok(parent) = v.parse::<u32>() else {
                return (400, format!("parent 非数字：{v}\n"));
            };
            let j = journal.read().expect("锁中毒");
            if parent >= j.dag().nodes().len() as u32 {
                return (404, format!("节点 #{parent:02} 不存在\n"));
            }
            let list: Vec<String> = taskmd::taskbar(&j, crate::NodeId(parent))
                .into_iter()
                .map(|(id, title)| format!("#{:02} {}", id.0, title))
                .collect();
            (200, format!("{}\n", list.join("\n")))
        }
        ("POST", "/v1/taskmd") => {
            // MD → 任务栏：body = Markdown 文本
            let mut parent: Option<u32> = None;
            let mut quarantine = false;
            let mut source = "HTTP".to_string();
            for (k, v) in query {
                match k.as_str() {
                    "parent" => parent = v.parse::<u32>().ok(),
                    "quarantine" => quarantine = v == "1" || v == "true",
                    "source" => source = v.clone(),
                    _ => {}
                }
            }
            let Some(parent) = parent else {
                return (400, "缺 parent 参数\n".into());
            };
            let r = {
                let mut j = journal.write().expect("锁中毒");
                taskmd::ingest(&mut j, crate::NodeId(parent), &source, body, quarantine)
            };
            match r {
                Ok(o) => (
                    200,
                    format!(
                        "created={} skipped={} quarantined={} zero_state_only=true\n",
                        o.created, o.skipped, o.quarantined
                    ),
                ),
                Err(e) => (400, format!("入账失败：{e}\n")),
            }
        }
        ("GET", "/v1/gate") => {
            let Some((_, v)) = query.iter().find(|(k, _)| k == "tip") else {
                return (400, "缺 tip 参数\n".into());
            };
            let Ok(tip) = v.parse::<u32>() else {
                return (400, format!("tip 非数字：{v}\n"));
            };
            let j = journal.read().expect("锁中毒");
            let len = j.dag().nodes().len() as u32;
            if tip >= len {
                return (404, format!("节点 #{tip:02} 不存在\n"));
            }
            let verdict = j.dag().node(crate::NodeId(tip)).verdict;
            let gate = j.dag().merge_gate(crate::NodeId(tip));
            (
                200,
                format!("node=#{tip:02} verdict={verdict} gate={gate}\n"),
            )
        }
        ("POST", "/v1/deltas") => match parse_frame_str(body) {
            Ok(frame) => {
                let out = {
                    let mut j = journal.write().expect("锁中毒");
                    sync::merge_into(&mut j, frame.writer, frame.stamped)
                };
                match out {
                    Ok(o) => {
                        let suspects = journal.read().expect("锁中毒").dag().suspects().len();
                        (
                            200,
                            format!(
                                "canonical={} deferred={} suspects={}\n",
                                o.canonical.len(),
                                o.deferred.len(),
                                suspects
                            ),
                        )
                    }
                    Err(e) => (500, format!("合并采纳失败：{e}\n")),
                }
            }
            Err(e) => (400, format!("帧解析失败：{e}\n")),
        },
        ("POST", "/v1/diag") => {
            // 编译器管线桥：body = 编译器诊断输出。?format= rustc(默认)|tsc|gcc|eslint
            let Some((_, v)) = query.iter().find(|(k, _)| k == "node") else {
                return (400, "缺 node 参数\n".into());
            };
            let Ok(node) = v.parse::<u32>() else {
                return (400, format!("node 非数字：{v}\n"));
            };
            let format = query
                .iter()
                .find(|(k, _)| k == "format")
                .map(|(_, v)| v.as_str())
                .unwrap_or("rustc");
            let diags = match format {
                "rustc" => {
                    // 守卫：垃圾输入拒绝（避免空 POST 把节点"洗"成 +1）；
                    // rustc 干净构建也输出 JSON（build-finished），所以 ≥1 行 JSON 是硬要求
                    if body.trim().is_empty() || !diag::has_json(body) {
                        return (
                            400,
                            "无诊断数据（应为 rustc --message-format=json 流）\n".into(),
                        );
                    }
                    diag::parse_rustc_stream(body)
                }
                "tsc" => {
                    // tsc 干净构建 stdout 为空——调用方约定发 `{}` 占位（非 JSON 横幅照发）；
                    // 守卫同 rustc：至少一行合法 JSON，垃圾输入照样 400
                    if body.trim().is_empty() || !diag::has_json(body) {
                        return (400, "无诊断数据（tsc 流；干净构建发 {} 占位）\n".into());
                    }
                    diag::parse_tsc_stream(body)
                }
                // gcc/clang 与 eslint：整个 body 一个 JSON 数组（干净输出 `[]`），
                // 不是数组 = 垃圾输入 → None → 400
                "gcc" => match diag::parse_gcc_json(body) {
                    Some(d) => d,
                    None => return (400, "无诊断数据（gcc 格式应为一个 JSON 数组）\n".into()),
                },
                "eslint" => match diag::parse_eslint_json(body) {
                    Some(d) => d,
                    None => return (400, "无诊断数据（eslint 格式应为一个 JSON 数组）\n".into()),
                },
                other => {
                    return (
                        400,
                        format!("未知 format：{other}（rustc|tsc|gcc|eslint）\n"),
                    )
                }
            };
            record_check_layer(journal, node, "编译层", &diags)
        }
        ("POST", "/v1/scan") => match parse_scan_body(body) {
            Ok(snippets) => {
                let refs: Vec<(crate::NodeId, &str)> =
                    snippets.iter().map(|(n, c)| (*n, c.as_str())).collect();
                let report = scan::run_scan(&refs, scan::RULES, &[]);
                let deltas = report.to_deltas("HTTP");
                let applied = (|| -> io::Result<usize> {
                    let mut j = journal.write().expect("锁中毒");
                    let mut n = 0usize;
                    for d in &deltas {
                        j.append_delta(d)
                            .map_err(|e| io::Error::other(e.to_string()))?;
                        n += 1;
                    }
                    Ok(n)
                })();
                match applied {
                    Ok(n) => (
                        200,
                        format!(
                            "scanned={} findings={} applied={} scanner_never_plus1=true\n",
                            report.scanned,
                            report.findings.len(),
                            n
                        ),
                    ),
                    Err(e) => (500, format!("写入失败：{e}\n")),
                }
            }
            Err(e) => (400, format!("{e}\n")),
        },
        ("POST", "/v1/lsp") => {
            // LSP 桥：body = publishDiagnostics 通知流（rust-analyzer 等）
            let Some((_, v)) = query.iter().find(|(k, _)| k == "node") else {
                return (400, "缺 node 参数\n".into());
            };
            let Ok(node) = v.parse::<u32>() else {
                return (400, format!("node 非数字：{v}\n"));
            };
            if body.trim().is_empty() || !diag::has_json(body) {
                return (400, "无诊断数据（应为 LSP 通知流）\n".into());
            }
            let diags = lsp::parse_lsp_stream(body)
                .into_iter()
                .map(|d| d.into_diag())
                .collect::<Vec<_>>();
            record_check_layer(journal, node, "LSP 层", &diags)
        }
        ("POST", "/v1/intake") => {
            // 设计决策生产线入口：分类（新决策/执行既有/退回设计队列）
            let mut title = "untitled".to_string();
            let mut touches: Vec<DesignArea> = Vec::new();
            let mut is_new = false;
            let mut adr: Option<String> = None;
            for (k, v) in query {
                match k.as_str() {
                    "title" => title = v.clone(),
                    "areas" => {
                        touches = v.split(',').filter_map(DesignArea::parse).collect();
                    }
                    "new" => is_new = v == "1" || v == "true",
                    "adr" => adr = Some(v.clone()),
                    _ => {}
                }
            }
            let intake = PrIntake {
                title,
                touches,
                is_new_decision: is_new,
                linked_adr: adr,
                impact_summary: None,
                rollback: None,
            };
            let routing = design::classify(&intake);
            (200, format!("routing={routing:?}\n"))
        }
        ("GET", "/v1/catalog") => {
            // 发现目录（只读视图）：族折叠 + 验证层级 + 修正注记——手稿清单 TSV
            let j = journal.read().expect("锁中毒");
            let cat = crate::catalog::catalog(j.dag());
            (200, crate::catalog::export_map_tsv(&cat))
        }
        ("POST", "/v1/triage-bridge") => {
            // trit-re 台账桥（ROADMAP #51）：body = trit-re 的 JSONL 台账；
            // ?parent=N（缺省 0）+ ?quarantine=0 解除自动隔离（缺省隔离）。
            // 三值对齐：true → -1、unknown → 0、false 不入账（扫描器永不 +1）。
            let parent = query
                .iter()
                .find(|(k, _)| k == "parent")
                .and_then(|(_, v)| v.parse::<u32>().ok())
                .unwrap_or(0);
            let quarantine = !query
                .iter()
                .any(|(k, v)| k == "quarantine" && (v == "0" || v == "false"));
            let len = {
                let j = journal.read().expect("锁中毒");
                j.dag().nodes().len() as u32
            };
            if parent >= len {
                return (404, format!("父节点 #{parent:02} 不存在\n"));
            }
            let mut j = journal.write().expect("锁中毒");
            match crate::retbridge::intake_triage(&mut j, crate::NodeId(parent), body, quarantine)
            {
                Ok(report) => (
                    200,
                    format!(
                        "samples={} findings={} vulnerable={} unknown={} skipped_false={} bad_lines={} quarantined={} scanner_never_plus1=true\n",
                        report.samples,
                        report.findings,
                        report.vulnerable,
                        report.unknown,
                        report.skipped_false,
                        report.bad_lines,
                        report.quarantined
                    ),
                ),
                Err(e) => (500, format!("入账失败：{e}\n")),
            }
        }
        ("GET", _) | ("POST", _) => (404, "未知路径\n".into()),
        _ => (405, "方法不允许\n".into()),
    }
}

fn parse_frame_str(body: &str) -> Result<LogFrame, String> {
    sync::parse_frame(body)
}

/// 扫描入账请求行格式：`SNIP\t<node>\t<转义代码>`（esc 转义，与日志同风格）。
fn parse_scan_body(body: &str) -> Result<Vec<(crate::NodeId, String)>, String> {
    let mut snippets = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let mut f = line.split('\t');
        match (f.next(), f.next(), f.next(), f.next()) {
            (Some("SNIP"), Some(node), Some(code), None) => {
                let n = node
                    .parse::<u32>()
                    .map_err(|_| format!("非法节点号：{node:?}"))?;
                let c = crate::delta::unesc(code)?;
                snippets.push((crate::NodeId(n), c));
            }
            _ => return Err("行格式应为 SNIP\\t<node>\\t<code>".into()),
        }
    }
    Ok(snippets)
}

/// 一次 HTTP 请求解析结果：方法 / 路径 / 查询对 / 请求体。
type ParsedRequest = (String, String, Vec<(String, String)>, String);

pub(crate) fn read_request<S: std::io::Read + std::io::Write>(
    stream: &mut S,
) -> io::Result<ParsedRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "请求头过大"));
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "连接提前关闭"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    for h in lines {
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if content_length > MAX_BODY {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "请求体过大"));
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    let body = String::from_utf8_lossy(&body).to_string();
    let (path, query_str) = target.split_once('?').unwrap_or((&target, ""));
    let query: Vec<(String, String)> = query_str
        .split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    Ok((method, path.to_string(), query, body))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn format_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// fleet 层 HTTP 面已拆至 [`crate::fleet_server`]（上游 module budget：
/// 单文件 ≤800 行）——类型路径经此 re-export 保持不变。
#[cfg(feature = "full")]
pub use crate::fleet_server::FleetServer;

/// 极简 HTTP 客户端（测试与脚本用；返回 (状态码, 响应体)）。
pub mod client {
    use super::*;

    pub fn get(addr: SocketAddr, path: &str) -> io::Result<(u16, String)> {
        request(addr, "GET", path, "")
    }

    pub fn post(addr: SocketAddr, path: &str, body: &str) -> io::Result<(u16, String)> {
        request(addr, "POST", path, body)
    }

    pub fn request(
        addr: SocketAddr,
        method: &str,
        path: &str,
        body: &str,
    ) -> io::Result<(u16, String)> {
        let mut s = TcpStream::connect(addr)?;
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: server\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes())?;
        let mut resp = Vec::new();
        s.read_to_end(&mut resp)?;
        let text = String::from_utf8_lossy(&resp).to_string();
        let mut lines = text.splitn(2, "\r\n\r\n");
        let head = lines.next().unwrap_or("");
        let body = lines.next().unwrap_or("").to_string();
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "响应无状态行"))?;
        Ok((status, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_server::route_fleet;

    fn temp_journal() -> Journal {
        // 文件名带原子计数器：并行测试同 pid 撞名会让 create_as 报"文件存在"
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "trit-immune-srv-t-{}-{n}.journal",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&p);
        Journal::create_as(&p, "t", 0).unwrap()
    }

    /// fleet 端点测试用的两仓舰队（各自 temp journal，上游 -1 / 下游 +1）。
    fn temp_fleet() -> Fleet {
        use crate::{NodeId, NodeKind, Trit};
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let (pa, pb) = (
            dir.join(format!(
                "trit-fleet-srv-a-{}-{n}.journal",
                std::process::id()
            )),
            dir.join(format!(
                "trit-fleet-srv-b-{}-{n}.journal",
                std::process::id()
            )),
        );
        let _ = std::fs::remove_file(&pa);
        let _ = std::fs::remove_file(&pb);
        let mut a = Journal::create_as(&pa, "up", 0).unwrap();
        let na = a.spawn(NodeId(0), NodeKind::Delta, "上游节点").unwrap();
        a.record(na, Trit::Vulnerable, None, "确认打穿").unwrap();
        drop(a.into_dag().unwrap());
        let mut b = Journal::create_as(&pb, "down", 1).unwrap();
        let nb = b.spawn(NodeId(0), NodeKind::Delta, "下游节点").unwrap();
        b.record(nb, Trit::Hardened, None, "自身通过").unwrap();
        drop(b.into_dag().unwrap());
        let mut f = Fleet::new();
        f.add("up", Journal::open_as(&pa, 0).unwrap()).unwrap();
        f.add("down", Journal::open_as(&pb, 1).unwrap()).unwrap();
        f
    }

    #[test]
    fn fleet_route_read_endpoints() {
        let f = temp_fleet();
        let shared = std::sync::RwLock::new(f);
        let (s, body) =
            crate::fleet_server::route_fleet(&shared, "GET", "/v1/fleet/health", &[], "");
        assert_eq!((s, body.trim()), (200, "ok"));
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/repos", &[], "");
        assert_eq!(s, 200);
        assert!(body.contains("up") && body.contains("down"), "{body}");
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/board", &[], "");
        assert_eq!(s, 200);
        assert!(body.starts_with("name\ttotal\thardened"), "{body}");
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/render", &[], "");
        assert_eq!(s, 200);
        assert!(!body.is_empty());
        // verdicts：缺参 400；有参返回表
        let (s, _) = route_fleet(&shared, "GET", "/v1/fleet/verdicts", &[], "");
        assert_eq!(s, 400, "缺 repo");
        let q = vec![("repo".to_string(), "down".to_string())];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/verdicts", &q, "");
        assert_eq!(s, 200);
        assert!(body.contains("node\tverdict"), "{body}");
        let q2 = vec![
            ("repo".to_string(), "down".to_string()),
            ("node".to_string(), "1".to_string()),
        ];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/verdict", &q2, "");
        assert_eq!((s, body.trim()), (200, "+1"));
        // 405 / 404
        let (s, _) = route_fleet(&shared, "POST", "/v1/fleet/board", &[], "");
        assert_eq!(s, 405);
        let (s, _) = route_fleet(&shared, "GET", "/v1/fleet/nope", &[], "");
        assert_eq!(s, 404);
    }

    #[test]
    fn fleet_route_catalog_endpoint() {
        let f = temp_fleet();
        let shared = std::sync::RwLock::new(f);
        // 无参：逐仓统计表（board 风格）
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/catalog", &[], "");
        assert_eq!(s, 200);
        assert!(
            body.starts_with(
                "name\tfindings\tfamilies\treproduced\tadjudicated\tclaimed\tcontradictions\tverified_ratio\n"
            ),
            "{body}"
        );
        assert!(
            body.contains("up\t1\t1\t0\t0\t1\t0\t0.0000"),
            "up 仓 1 发现 1 族，无证据 -1 = 纯声称 ratio 0：{body}"
        );
        assert!(
            body.contains("down\t1\t1\t0\t1\t0\t0\t1.0000"),
            "down 仓 +1 = 已裁定 ratio 1：{body}"
        );
        // ?repo=：该仓完整手稿清单 TSV
        let q = vec![("repo".to_string(), "up".to_string())];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/catalog", &q, "");
        assert_eq!(s, 200);
        assert!(body.starts_with("# trit-immune catalog map v1"), "{body}");
        assert!(
            body.contains("NODE\t1\tdelta\tclaimed\t-1\tfalse\t上游节点"),
            "层级=证据形态（无证据 -1 是 claimed 不是 adjudicated）：{body}"
        );
        // 未知仓 404；已知端点方法错 405
        let q2 = vec![("repo".to_string(), "ghost".to_string())];
        let (s, _) = route_fleet(&shared, "GET", "/v1/fleet/catalog", &q2, "");
        assert_eq!(s, 404);
        let (s, _) = route_fleet(&shared, "POST", "/v1/fleet/catalog", &[], "");
        assert_eq!(s, 405, "KNOWN 表已收 catalog");
    }

    #[test]
    fn fleet_route_attacks_endpoint() {
        let f = temp_fleet();
        let shared = std::sync::RwLock::new(f);
        // 声明确认穿透边：up#1(-1) → down#1(+1)
        let (s, _) = route_fleet(
            &shared,
            "POST",
            "/v1/fleet/links",
            &[],
            "up\t1\tdown\t1\t-1\t穿透\n",
        );
        assert_eq!(s, 200);
        let q = vec![
            ("repo".to_string(), "down".to_string()),
            ("node".to_string(), "1".to_string()),
        ];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/attacks", &q, "");
        assert_eq!(s, 200, "{body}");
        assert!(body.starts_with("chains=1 truncated=false"), "{body}");
        assert!(
            body.contains("\tsource\n") && body.contains("\tcrosslink\n"),
            "{body}"
        );
        // 缺参 400
        let (s, _) = route_fleet(&shared, "GET", "/v1/fleet/attacks", &[], "");
        assert_eq!(s, 400);
        // 自定义上限
        let q2 = vec![
            ("repo".to_string(), "down".to_string()),
            ("node".to_string(), "1".to_string()),
            ("max_chains".to_string(), "1".to_string()),
        ];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/attacks", &q2, "");
        assert_eq!(s, 200);
        assert!(body.starts_with("chains=1"), "{body}");
    }

    #[test]
    fn fleet_route_write_and_sync_end_to_end() {
        let f = temp_fleet();
        let shared = std::sync::RwLock::new(f);

        // 声明跨仓边：up#1 → down#1，确认穿透
        let (s, body) = route_fleet(
            &shared,
            "POST",
            "/v1/fleet/links",
            &[],
            "up\t1\tdown\t1\t-1\t确认穿透\n",
        );
        assert_eq!((s, body.trim()), (200, "links=1"));
        // 坏行拒绝
        let (s, _) = route_fleet(&shared, "POST", "/v1/fleet/links", &[], "垃圾行\n");
        assert_eq!(s, 400);

        // sync：-1 沿边落账
        let (s, body) = route_fleet(&shared, "POST", "/v1/fleet/sync", &[], "端到端反熵");
        assert_eq!(s, 200, "{body}");
        assert!(body.starts_with("landed=1"), "{body}");

        // 幂等：再 sync 零落账
        let (s, body) = route_fleet(&shared, "POST", "/v1/fleet/sync", &[], "");
        assert_eq!(s, 200);
        assert!(body.starts_with("landed=0"), "{body}");

        // 落账事实可见：down#1 现在 -1
        let q = vec![
            ("repo".to_string(), "down".to_string()),
            ("node".to_string(), "1".to_string()),
        ];
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/verdict", &q, "");
        assert_eq!((s, body.trim()), (200, "-1"));

        // record 原语：人工复核复原
        let (s, body) = route_fleet(
            &shared,
            "POST",
            "/v1/fleet/record",
            &[],
            "down\t1\t+1\t人工复核通过",
        );
        assert_eq!((s, body.trim()), (200, "recorded down#1=+1"));
        let (s, body) = route_fleet(&shared, "GET", "/v1/fleet/verdict", &q, "");
        assert_eq!((s, body.trim()), (200, "+1"));
    }

    #[test]
    fn fleet_server_tcp_smoke() {
        use crate::server::client;
        let f = temp_fleet();
        let srv = FleetServer::new(f);
        let addr = srv
            .serve(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap();
        let (s, body) = client::get(addr, "/v1/fleet/health").unwrap();
        assert_eq!((s, body.trim()), (200, "ok"));
        let (s, _) = client::post(addr, "/v1/fleet/links", "up\t1\tdown\t1\t-1\t穿透\n").unwrap();
        assert_eq!(s, 200);
        let (s, body) = client::post(addr, "/v1/fleet/sync", "tcp 反熵").unwrap();
        assert_eq!(s, 200);
        assert!(body.starts_with("landed=1"), "{body}");
    }

    #[test]
    fn routing_status_codes() {
        let j = RwLock::new(temp_journal());
        let (status, _) = route(&j, "GET", "/v1/health", &[], "");
        assert_eq!(status, 200);
        let (status, _) = route(&j, "DELETE", "/v1/health", &[], "");
        assert_eq!(status, 405);
        let (status, _) = route(&j, "GET", "/v1/nope", &[], "");
        assert_eq!(status, 404);
        let (status, _) = route(&j, "GET", "/v1/gate", &[], "");
        assert_eq!(status, 400, "缺 tip 参数");
    }

    #[test]
    fn catalog_endpoint_read_only_map() {
        use crate::{NodeId, NodeKind, Trit};
        let mut j = temp_journal();
        let a = j
            .spawn(NodeId(0), NodeKind::Delta, "sql 注入（login）")
            .unwrap();
        let b = j
            .spawn(NodeId(0), NodeKind::AttackVector, "SQL 注入 (admin)")
            .unwrap();
        j.record(a, Trit::Vulnerable, None, "打穿").unwrap();
        j.record(b, Trit::Unknown, None, "声称").unwrap();
        let j = RwLock::new(j);
        let (s, body) = route(&j, "GET", "/v1/catalog", &[], "");
        assert_eq!(s, 200);
        assert!(
            body.starts_with("# trit-immune catalog map v1"),
            "手稿清单 TSV 形态：{body}"
        );
        assert!(
            body.contains("FAM\tsql 注入"),
            "同根因两节点折叠成族：{body}"
        );
        assert!(
            body.contains("NODE\t2\tattack\tclaimed\t0\tfalse"),
            "层级/裁决/隔离逐列在 TSV：{body}"
        );
        assert!(body.ends_with("# correction\tnode\tkind\n"), "修正段收尾");
        // POST 走未知路径兜底（单仓路由的既有约定）
        let (s, _) = route(&j, "POST", "/v1/catalog", &[], "");
        assert_eq!(s, 404);
    }

    #[test]
    fn triage_bridge_endpoint_bridges_real_jsonl() {
        use crate::{NodeId, NodeKind, Trit};
        let mut j = temp_journal();
        let host = j.spawn(NodeId(0), NodeKind::Delta, "宿主").unwrap();
        let j = RwLock::new(j);
        let jsonl = concat!(
            r#"{"kind":"file","schema":3,"sha256":"beef","size":5}"#,
            "\n",
            r#"{"kind":"judgment","sha256":"beef","id":"injection","title":"远程注入","value":"true","four":"T","support":[],"refute":[],"unknown":[]}"#,
            "\n",
            r#"{"kind":"judgment","sha256":"beef","id":"packed","title":"加壳","value":"false","four":"N","support":[],"refute":[],"unknown":[]}"#,
            "\n",
        );
        let q = vec![("parent".to_string(), host.0.to_string())];
        let (s, body) = route(&j, "POST", "/v1/triage-bridge", &q, jsonl);
        assert_eq!(s, 200, "{body}");
        assert!(body.contains("samples=1"), "{body}");
        assert!(body.contains("vulnerable=1"), "true → -1：{body}");
        assert!(body.contains("skipped_false=1"), "False 不入账：{body}");
        assert!(body.contains("scanner_never_plus1=true"), "{body}");
        // 账面：样本节点挂宿主下（隔离），发现挂样本下（true → -1）
        let dag = j.read().expect("锁").dag().clone();
        let sample = dag
            .nodes()
            .iter()
            .find(|n| n.parent == Some(host) && n.title.contains("trit-re 样本 beef"))
            .expect("样本节点在账")
            .id;
        assert!(dag.node(sample).quarantined, "外部输入自动隔离");
        let findings: Vec<_> = dag
            .nodes()
            .iter()
            .filter(|n| n.parent == Some(sample))
            .collect();
        assert_eq!(findings.len(), 1, "true 判定一条发现（false 不入账）");
        assert_eq!(
            findings[0].verdict,
            Trit::Vulnerable,
            "true → -1（扫描器永不 +1：false 那条没进来）"
        );
        // 缺父 404
        let bad_q = vec![("parent".to_string(), "99".to_string())];
        let (s, _) = route(&j, "POST", "/v1/triage-bridge", &bad_q, jsonl);
        assert_eq!(s, 404);
    }
}
