//! TLS 传输层（`tls` feature flag 启用，默认关闭保持零依赖）。
//!
//! 生产部署推荐：**反向代理（nginx/caddy）终结 TLS**，内核只看到明文 TCP + HMAC。
//! 本模块供**不经代理的直连场景**使用（内网点对点）：
//! - [`Server::serve_tls`](crate::server::Server::serve_tls) /
//!   [`FleetServer::serve_tls`](crate::fleet_server::FleetServer::serve_tls)：
//!   HTTP 面的 TLS 直连（先握手再进同一个连接循环，路由/账本/纪律全同明文版）；
//! - [`accept`]/[`connect`]：把一条已连 TCP 流升级成 TLS 流的薄包装
//!   （握手惰性——首次读写时完成；明文客户端会在握手处失败，服务端如实丢弃）。
//!
//! 认证与加密分层：TLS 管**管道**（机密性/对端身份），PSK 帧认证
//! （`sync::sign_frame`/`verify_frame`）管**内容**——两层独立，叠加不冲突。
//! 证书：生产用 CA 签发；测试用 `generate_self_signed` 自签。
#![cfg(feature = "tls")]

/// rustls 的再导出：调用方（server 的 TLS 形态、测试）需要 `ServerConfig`
/// 等类型，但 rustls 是可选依赖——只能从这里拿，不能裸引。
pub use rustls;

use std::io;
use std::net::TcpStream;

/// TLS 配置：证书路径 + 私钥路径。
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// 生成自签名证书（测试/开发用；生产用 CA 签发）。
pub fn generate_self_signed(hostname: &str) -> Result<(String, String), String> {
    let cert = rcgen::generate_simple_self_signed(vec![hostname.to_string()])
        .map_err(|e| format!("证书生成失败：{e}"))?;
    Ok((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

/// 创建 rustls 服务端配置。
pub fn server_config(cert_pem: &str, key_pem: &str) -> Result<rustls::ServerConfig, String> {
    let mut certs = Vec::new();
    for chunk in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
        certs.push(chunk.map_err(|e| format!("证书解析失败：{e}"))?);
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("私钥解析失败：{e}"))?
        .ok_or("私钥为空")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("服务端 TLS 配置失败：{e}"))?;
    Ok(config)
}

/// 把一条已连 TCP 流升级为 TLS 服务端流（首次读写时完成握手）。
/// 每条 TLS 连接的读写上限。没有它，明文或畸形客户端会让服务端线程
/// 永远等在握手上（实测把一个 `cargo test` 挂死 >60 秒），
/// 一个只会拒绝明文的 TLS 端口照样能被廉价拖光线程。
pub const CONNECTION_TIMEOUT: Option<std::time::Duration> =
    Some(std::time::Duration::from_secs(30));

pub fn accept(
    config: &rustls::ServerConfig,
    sock: TcpStream,
) -> io::Result<rustls::StreamOwned<rustls::ServerConnection, TcpStream>> {
    // 先设期限再交出去：rustls 的握手是惰性的（首次读写才发生），在这里设才对整条连接生效
    sock.set_read_timeout(CONNECTION_TIMEOUT)?;
    sock.set_write_timeout(CONNECTION_TIMEOUT)?;
    let conn = rustls::ServerConnection::new(std::sync::Arc::new(config.clone()))
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// 把一条已连 TCP 流升级为 TLS 客户端流（首次读写时完成握手）。
pub fn connect(
    config: &rustls::ClientConfig,
    server_name: &str,
    sock: TcpStream,
) -> io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("服务器名不合法：{e}")))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config.clone()), name)
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(rustls::StreamOwned::new(conn, sock))
}

/// 创建 rustls 客户端配置（信任自签证书或跳过校验——仅测试用）。
pub fn client_config_skip_verify() -> Result<rustls::ClientConfig, String> {
    use std::sync::Arc;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    Ok(config)
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
