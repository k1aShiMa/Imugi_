/// Packet forwarding loop — Linux node side.
///
/// Reads raw IP packets from an AF_PACKET raw socket (captures all inbound),
/// sends them to the proxy over TLS, and injects proxy-sourced packets back
/// into the network stack via an AF_INET/IPPROTO_RAW socket.
///
/// Requires CAP_NET_RAW (less than full root, more attainable).
 
use anyhow::{bail, Context, Result};
use imugi_common::{decode_len, encode_packet, DATA_HEADER_LEN};
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
 
const MTU: usize = 1500;
 
pub async fn run_forwarding(
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<()> {
    let rx_fd = open_raw_rx().context("Open RX raw socket")?;
    let tx_fd = open_raw_tx().context("Open TX raw socket")?;
 
    info!("Raw sockets open (rx={}, tx={})", rx_fd, tx_fd);
 
    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);
 
    // Wrap RX socket fd in tokio AsyncFd for non-blocking reads
    let rx_file: std::fs::File = unsafe { FromRawFd::from_raw_fd(rx_fd) };
    let raw_rx = tokio::io::unix::AsyncFd::new(rx_file)
        .context("AsyncFd for RX socket")?;
 
    // TLS reader → raw socket injector
    let tx_handle = tokio::spawn(async move {
        let mut header = [0u8; DATA_HEADER_LEN];
        loop {
            match tls_rx.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Proxy disconnected");
                    break;
                }
                Err(e) => { warn!("TLS read: {}", e); break; }
            }
 
            let len = decode_len(&header);
            if len == 0 || len > 65535 { warn!("Bad len {}", len); continue; }
 
            let mut pkt = vec![0u8; len];
            if tls_rx.read_exact(&mut pkt).await.is_err() { break; }
 
            if let Err(e) = inject_packet(tx_fd, &pkt) {
                error!("Inject: {}", e);
            }
        }
    });
 
    // Raw socket reader → TLS writer
    let mut read_buf = vec![0u8; MTU + 18]; // +18 for ethernet frame header (AF_PACKET gives L2)
    loop {
        let mut guard = raw_rx.readable().await?;
 
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::recv(
                    std::os::unix::io::AsRawFd::as_raw_fd(inner.get_ref()),
                    read_buf.as_mut_ptr() as *mut libc::c_void,
                    read_buf.len(),
                    0,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(n)) if n > 14 => {
                // AF_PACKET gives us L2 frame — skip 14-byte ethernet header to get IP
                let ip_pkt = &read_buf[14..n];
                let framed = encode_packet(ip_pkt);
                if tls_tx.write_all(&framed).await.is_err() {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => { warn!("Raw recv: {}", e); }
            Err(_) => { guard.clear_ready(); }
        }
    }
 
    tx_handle.abort();
    Ok(())
}
 
fn open_raw_rx() -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        bail!("socket(AF_PACKET): {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}
 
fn open_raw_tx() -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)
    };
    if fd < 0 {
        bail!("socket(AF_INET, IPPROTO_RAW): {}", std::io::Error::last_os_error());
    }
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd, libc::IPPROTO_IP, libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    Ok(fd)
}
 
fn inject_packet(fd: RawFd, pkt: &[u8]) -> Result<()> {
    if pkt.len() < 20 {
        bail!("Packet too short ({}b)", pkt.len());
    }
    let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: u32::from(dst).to_be() },
        sin_zero: [0; 8],
    };
    let n = unsafe {
        libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        bail!("sendto: {}", std::io::Error::last_os_error());
    }
    Ok(())
}