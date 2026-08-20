/// Packet forwarding loop — Linux and Windows node side.
///
/// Reads raw IP packets from the network stack and forwards them over TLS,
/// injecting proxy-sourced packets back into the local stack.
///
/// Requires elevated privileges:
///   Linux   — CAP_NET_RAW or root
///   Windows — Administrator

use anyhow::Result;

pub async fn run_forwarding(
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::run_forwarding(tls).await;

    #[cfg(windows)]
    return windows::run_forwarding(tls).await;

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = tls;
        anyhow::bail!("Packet forwarding is only supported on Linux and Windows");
    }
}

// ── Linux ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{bail, Context, Result};
    use imugi_common::{decode_len, encode_packet, DATA_HEADER_LEN};
    use libc::sa_family_t;
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

        let rx_file: std::fs::File = unsafe { FromRawFd::from_raw_fd(rx_fd) };
        let raw_rx = tokio::io::unix::AsyncFd::new(rx_file)
            .context("AsyncFd for RX socket")?;

        let tx_handle = tokio::spawn(async move {
            let mut header = [0u8; DATA_HEADER_LEN];
            loop {
                match tls_rx.read_exact(&mut header).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        info!("Proxy disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!("TLS read: {}", e);
                        break;
                    }
                }
                let len = decode_len(&header);
                if len == 0 || len > 65535 {
                    warn!("Bad len {}", len);
                    continue;
                }
                let mut pkt = vec![0u8; len];
                if tls_rx.read_exact(&mut pkt).await.is_err() {
                    break;
                }
                if let Err(e) = inject_packet(tx_fd, &pkt) {
                    error!("Inject: {}", e);
                }
            }
        });

        let mut read_buf = vec![0u8; MTU + 18];
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
                    // AF_PACKET gives L2 frame — skip 14-byte ethernet header
                    let ip_pkt = &read_buf[14..n];
                    let framed = encode_packet(ip_pkt);
                    if tls_tx.write_all(&framed).await.is_err() {
                        break;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    warn!("Raw recv: {}", e);
                }
                Err(_) => {
                    guard.clear_ready();
                }
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
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if fd < 0 {
            bail!("socket(AF_INET, IPPROTO_RAW): {}", std::io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
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
            sin_family: libc::AF_INET as u16 as sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst).to_be(),
            },
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
}

// ── Windows ───────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod windows {
    use anyhow::{bail, Result};
    use imugi_common::{decode_len, encode_packet, DATA_HEADER_LEN};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use tracing::{error, info, warn};
    use windows_sys::Win32::Networking::WinSock::{
        bind, closesocket, recv, sendto, setsockopt, socket, WSACleanup, WSAGetLastError,
        WSAIoctl, WSAStartup, AFD_PARTIAL_DISCONNECT_INFO, AF_INET, IN_ADDR, IN_ADDR_0,
        INVALID_SOCKET, IPPROTO_IP, IPPROTO_RAW, IP_HDRINCL, RCVALL_ON, SIO_RCVALL,
        SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOCK_RAW, WSADATA,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    use std::mem;

    pub async fn run_forwarding(
        tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    ) -> Result<()> {
        unsafe {
            let mut wsa_data = mem::zeroed::<WSADATA>();
            let ret = WSAStartup(0x0202, &mut wsa_data);
            if ret != 0 {
                bail!("WSAStartup failed: {}", ret);
            }
        }

        let local_ip_be = get_local_ip_be()?;
        let rx_sock = create_rx_socket(local_ip_be)?;
        let tx_sock = create_tx_socket()?;

        info!("Raw sockets open");

        let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);

        // Blocking thread: recv from raw socket → channel (SIO_RCVALL gives raw IP, no L2 header)
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(256);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = unsafe { recv(rx_sock, buf.as_mut_ptr(), buf.len() as i32, 0) };
                if n == SOCKET_ERROR || n <= 0 {
                    break;
                }
                let pkt = buf[..n as usize].to_vec();
                if raw_tx.blocking_send(pkt).is_err() {
                    break;
                }
            }
            unsafe { closesocket(rx_sock) };
        });

        // TLS reader → inject packets into local stack
        let tx_handle = tokio::spawn(async move {
            let mut header = [0u8; DATA_HEADER_LEN];
            loop {
                match tls_rx.read_exact(&mut header).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        info!("Proxy disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!("TLS read: {}", e);
                        break;
                    }
                }
                let len = decode_len(&header);
                if len == 0 || len > 65535 {
                    warn!("Bad len {}", len);
                    continue;
                }
                let mut pkt = vec![0u8; len];
                if tls_rx.read_exact(&mut pkt).await.is_err() {
                    break;
                }
                tokio::task::block_in_place(|| {
                    if let Err(e) = inject_packet(tx_sock, &pkt) {
                        error!("Inject: {}", e);
                    }
                });
            }
            unsafe { closesocket(tx_sock) };
        });

        // Forward captured packets to proxy over TLS
        while let Some(pkt) = raw_rx.recv().await {
            let framed = encode_packet(&pkt);
            if tls_tx.write_all(&framed).await.is_err() {
                break;
            }
        }

        tx_handle.abort();
        unsafe { WSACleanup() };
        Ok(())
    }

    fn get_local_ip_be() -> Result<u32> {
        use std::net::UdpSocket;
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect("8.8.8.8:80")?;
        match sock.local_addr()?.ip() {
            std::net::IpAddr::V4(ip) => Ok(u32::from(ip).to_be()),
            _ => bail!("No local IPv4 address found"),
        }
    }

    fn create_rx_socket(local_ip_be: u32) -> Result<SOCKET> {
        let sock = unsafe {
            socket(AF_INET as i32, SOCK_RAW as i32, IPPROTO_IP)
        };
        if sock == INVALID_SOCKET {
            bail!("socket(AF_INET, SOCK_RAW, IPPROTO_IP) failed — run as Administrator");
        }

        let addr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 { S_addr: local_ip_be },
            },
            sin_zero: [0; 8],
        };
        if unsafe {
            bind(
                sock,
                &addr as *const _ as *const SOCKADDR,
                mem::size_of::<SOCKADDR_IN>() as i32,
            )
        } == SOCKET_ERROR
        {
            unsafe { closesocket(sock) };
            bail!("bind failed for RX socket");
        }

        // Enable capture of all inbound IP packets on this interface
        let mut bytes_returned: u32 = 0;
        let rcvall: u32 = RCVALL_ON as u32;
        if unsafe {
            WSAIoctl(
                sock,
                SIO_RCVALL,
                &rcvall as *const _ as *const core::ffi::c_void,
                mem::size_of::<u32>() as u32,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut::<OVERLAPPED>(),
                None,
            )
        } == SOCKET_ERROR
        {
            unsafe { closesocket(sock) };
            bail!("WSAIoctl(SIO_RCVALL) failed — run as Administrator");
        }

        Ok(sock)
    }

    fn create_tx_socket() -> Result<SOCKET> {
        let sock = unsafe {
            socket(AF_INET as i32, SOCK_RAW as i32, IPPROTO_RAW)
        };
        if sock == INVALID_SOCKET {
            bail!("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed — run as Administrator");
        }
        let one: u32 = 1;
        unsafe {
            setsockopt(
                sock,
                IPPROTO_IP,
                IP_HDRINCL as i32,
                &one as *const _ as *const u8,
                mem::size_of::<u32>() as i32,
            )
        };
        Ok(sock)
    }

    fn inject_packet(sock: SOCKET, pkt: &[u8]) -> Result<()> {
        if pkt.len() < 20 {
            bail!("Packet too short ({}b)", pkt.len());
        }
        let dst = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let addr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from(dst).to_be(),
                },
            },
            sin_zero: [0; 8],
        };
        let n = unsafe {
            sendto(
                sock,
                pkt.as_ptr(),
                pkt.len() as i32,
                0,
                &addr as *const _ as *const SOCKADDR,
                mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if n == SOCKET_ERROR {
            bail!("sendto failed: {}", unsafe { WSAGetLastError() });
        }
        Ok(())
    }
}
