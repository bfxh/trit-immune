#![cfg(all(feature = "tls", feature = "full"))]
//! TLS 直连形态：自签证书 + rustls 完整握手（真实回环 TCP）。
//!
//! 锁三件事：
//! 1. TLS 客户端拿到与明文版逐字一致的响应（路由/账本/纪律全同，只有传输层换了）；
//! 2. 明文客户端连 TLS 端口在握手处失败——不得拿到任何合法 HTTP 响应；
//! 3. 写路径（POST /v1/diag）经 TLS 落账语义不变（检查类可为 +1）。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use trit_immune::tls;
use trit_immune::*;

fn temp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "trit-immune-tls-{name}-{}.journal",
        std::process::id()
    ))
}

fn server_config() -> tls::rustls::ServerConfig {
    let (cert, key) = tls::generate_self_signed("localhost").unwrap();
    tls::server_config(&cert, &key).unwrap()
}

fn client_config() -> tls::rustls::ClientConfig {
    tls::client_config_skip_verify().unwrap()
}

/// 自签证书链的 TLS 客户端请求：返回 (状态码, 响应体)。
/// 读循环容忍"裸 EOF"：对端不发 close_notify 时 rustls 先交出已缓冲明文、
/// 再报 UnexpectedEof——数据本身有效，如实收下（标准库语义下的半关闭）。
fn tls_request(
    addr: SocketAddr,
    ccfg: &tls::rustls::ClientConfig,
    req: &str,
) -> std::io::Result<(u16, String)> {
    use std::io::ErrorKind;
    use std::time::Duration;
    let sock = TcpStream::connect(addr)?;
    // 客户端也要有期限：没有它，任何一侧卡住就是把整个测试挂死（今天就是这么挂的）
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut s = tls::connect(ccfg, "localhost", sock)?;
    s.write_all(req.as_bytes())?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    let resp = String::from_utf8_lossy(&resp).to_string();
    let status: u16 = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

fn http_get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n")
}

fn journal_with_node(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let mut j = Journal::create_as(path, "main", 0).unwrap();
    let _ = j.spawn(NodeId(0), NodeKind::Delta, "功能").unwrap();
    j.into_dag().unwrap();
}

#[test]
fn tls_server_roundtrip_and_plaintext_rejected() {
    let p = temp("srv");
    journal_with_node(&p);
    let server = Server::new(Journal::open_as(&p, 0).unwrap());
    let addr = server
        .serve_tls("127.0.0.1:0".parse().unwrap(), server_config())
        .unwrap();
    let ccfg = client_config();

    // TLS 客户端：合法 HTTP 响应（与明文版同一路由）
    let (s, b) = tls_request(addr, &ccfg, &http_get("/v1/health")).unwrap();
    assert_eq!((s, b.trim()), (200, "ok"));
    let (s, b) = tls_request(addr, &ccfg, &http_get("/v1/render")).unwrap();
    assert_eq!(s, 200);
    assert!(b.contains("#01 DELTA"), "TLS 形态的响应应与明文版一致：{b}");

    // 明文客户端连 TLS 端口：握手失败，不得拿到任何合法 HTTP 响应。
    // 必须有超时：服务端等不到合法 ClientHello 时不会回东西，裸 read_to_string 会永远挂着
    // （这正是 tls_server_roundtrip_and_plaintext_rejected 把 `cargo test` 挂死 60s+ 的原因）。
    {
        use std::time::Duration;
        let mut plain = TcpStream::connect(addr).unwrap();
        plain
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        plain.write_all(http_get("/v1/health").as_bytes()).unwrap();
        let mut buf = String::new();
        let read = plain.read_to_string(&mut buf);
        assert!(
            read.is_err() || !buf.contains("200 OK"),
            "明文客户端不得拿到合法响应：{buf:?}（read={read:?}）"
        );
    } // 这里关掉明文连接：服务端的握手随之失败并释放线程，不许留僵尸线程

    // 明文探测之后服务器必须还活着（一条畸形连接不能把它拖死或卡死）
    let (s, _b) = tls_request(addr, &ccfg, &http_get("/v1/health")).unwrap();
    assert_eq!(s, 200, "明文探测之后 TLS 服务仍应正常应答");

    let _ = std::fs::remove_file(&p);
}

#[test]
fn diag_post_over_tls_records_layer() {
    // 写路径经 TLS：落账语义不变（干净构建 → 检查类 +1）
    let p = temp("diag");
    journal_with_node(&p);
    let server = Server::new(Journal::open_as(&p, 0).unwrap());
    let addr = server
        .serve_tls("127.0.0.1:0".parse().unwrap(), server_config())
        .unwrap();

    let body = r#"{"reason":"build-finished","success":true}"#;
    let req = format!(
        "POST /v1/diag?node=1 HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let (s, b) = tls_request(addr, &client_config(), &req).unwrap();
    assert_eq!(s, 200);
    assert!(b.contains("layer=+1"), "{b}");

    // 落账进了同一个 journal（重开可见）
    let j = Journal::open_as(&p, 0).unwrap();
    assert_eq!(
        j.dag().node(NodeId(1)).verdict,
        Trit::Hardened,
        "TLS 通道写入的层裁决必须进账本"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn fleet_server_over_tls() {
    let p = temp("fleet");
    let _ = std::fs::remove_file(&p);
    let j = Journal::create_as(&p, "r", 0).unwrap();
    let mut fleet = Fleet::new();
    fleet.add("r", j).unwrap();
    let server = FleetServer::new(fleet);
    let addr = server
        .serve_tls("127.0.0.1:0".parse().unwrap(), server_config())
        .unwrap();

    let (s, b) = tls_request(addr, &client_config(), &http_get("/v1/fleet/health")).unwrap();
    assert_eq!((s, b.trim()), (200, "ok"));
    let (s, b) = tls_request(addr, &client_config(), &http_get("/v1/fleet/board")).unwrap();
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("r"), "舰队聚合表应含仓 r：{b}");

    let _ = std::fs::remove_file(&p);
}
