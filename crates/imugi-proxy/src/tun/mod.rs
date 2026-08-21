/// TUN interface management.
///
/// On Linux/macOS: creates a kernel TUN device using the `tun` crate.
/// On Windows: TUN via the `tun` crate is not supported; this module
///   provides the same API surface but returns errors on creation.
///   Run the proxy on Linux for full functionality.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub const TUN_MTU: usize = 1500;

// ── TunDevice ─────────────────────────────────────────────────────────────────

#[cfg(unix)]
pub struct TunDevice {
    pub name: String,
    inner: tun::AsyncDevice,
}

#[cfg(windows)]
pub struct TunDevice {
    pub name: String,
}

impl TunDevice {
    pub fn new(name: &str, addr: &str, netmask: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            let addr_ip: Ipv4Addr = addr.parse().context("Invalid TUN addr")?;
            let mask_ip: Ipv4Addr = netmask.parse().context("Invalid TUN netmask")?;

            // macOS only accepts utun<N> interface names (kernel restriction).
            // Auto-prefix if the user passed a Linux-style name.
            #[cfg(target_os = "macos")]
            let effective_name: String = if name.starts_with("utun") {
                name.to_owned()
            } else {
                warn!(
                    "macOS requires utun<N> interface names; '{}' is invalid. \
                     Using 'utun0' — pass --tun-name utun0 to suppress this warning.",
                    name
                );
                "utun0".to_owned()
            };
            #[cfg(not(target_os = "macos"))]
            let effective_name = name.to_owned();

            let mut config = tun::Configuration::default();
            config
                .name(&effective_name)
                .address(addr_ip)
                .netmask(mask_ip)
                .mtu(TUN_MTU as i32)
                .up();

            #[cfg(target_os = "linux")]
            config.platform(|p| {
                p.packet_information(false);
            });

            let dev = tun::create_as_async(&config)
                .context("Failed to create TUN device — are you root?")?;

            info!("TUN interface '{}' up at {}", effective_name, addr);
            Ok(TunDevice { name: effective_name, inner: dev })
        }

        #[cfg(windows)]
        {
            let _ = (addr, netmask);
            bail!(
                "TUN interfaces are not supported on Windows. \
                 Run imugi-proxy on Linux."
            );
        }
    }

    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; TUN_MTU + 4];
            let n = self.inner.read(&mut buf).await.context("TUN read failed")?;
            if n == 0 {
                bail!("TUN device EOF");
            }
            buf.truncate(n);
            Ok(buf)
        }
        #[cfg(windows)]
        bail!("TUN not supported on Windows");
    }

    pub async fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        #[cfg(unix)]
        {
            use tokio::io::AsyncWriteExt;
            self.inner.write_all(pkt).await.context("TUN write failed")?;
            Ok(())
        }
        #[cfg(windows)]
        {
            let _ = pkt;
            bail!("TUN not supported on Windows");
        }
    }

    pub fn add_route(&self, subnet: &str) -> Result<()> {
        info!("Adding route {} via {}", subnet, self.name);
        add_route_impl(subnet, &self.name)
    }

    pub fn del_route(&self, subnet: &str) {
        let _ = del_route_impl(subnet, &self.name);
        info!("Removed route {}", subnet);
    }
}

// ── Route management ──────────────────────────────────────────────────────────

#[cfg(unix)]
fn add_route_impl(subnet: &str, iface: &str) -> Result<()> {
    use std::process::Command;
    let out = Command::new("ip")
        .args(["route", "add", subnet, "dev", iface])
        .output()
        .context("Failed to run 'ip route add'")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("File exists") {
            warn!("Route {} already exists, skipping", subnet);
        } else {
            bail!("ip route add failed: {}", stderr.trim());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn del_route_impl(subnet: &str, iface: &str) -> Result<()> {
    use std::process::Command;
    Command::new("ip")
        .args(["route", "del", subnet, "dev", iface])
        .output()
        .context("ip route del failed")?;
    Ok(())
}

#[cfg(windows)]
fn add_route_impl(subnet: &str, iface: &str) -> Result<()> {
    use std::process::Command;

    // Parse "network/prefix" into network + mask for Windows `route ADD`
    let (network, mask) = cidr_to_network_mask(subnet)?;
    let out = Command::new("route")
        .args(["ADD", &network, "MASK", &mask, iface])
        .output()
        .context("Failed to run 'route ADD'")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("route ADD failed: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(windows)]
fn del_route_impl(subnet: &str, iface: &str) -> Result<()> {
    use std::process::Command;
    let (network, mask) = cidr_to_network_mask(subnet)?;
    Command::new("route")
        .args(["DELETE", &network, "MASK", &mask, iface])
        .output()
        .context("route DELETE failed")?;
    Ok(())
}

#[cfg(windows)]
fn cidr_to_network_mask(cidr: &str) -> Result<(String, String)> {
    let mut parts = cidr.splitn(2, '/');
    let network = parts.next().unwrap_or("").to_string();
    let prefix: u32 = parts
        .next()
        .unwrap_or("32")
        .parse()
        .context("Invalid CIDR prefix")?;
    let mask_bits: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
    let mask = Ipv4Addr::from(mask_bits).to_string();
    Ok((network, mask))
}

// ── IP forwarding ─────────────────────────────────────────────────────────────

pub fn enable_ip_forwarding() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
            .context("Failed to enable IP forwarding — are you root?")?;
        info!("IP forwarding enabled");
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        let out = Command::new("netsh")
            .args(["interface", "ipv4", "set", "global", "forwarding=enabled"])
            .output()
            .context("Failed to run netsh to enable IP forwarding")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("netsh forwarding failed: {}", stderr.trim());
        }
        info!("IP forwarding enabled via netsh");
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        match Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .output()
        {
            Ok(out) if out.status.success() => info!("IP forwarding enabled via sysctl"),
            Ok(out) => warn!(
                "Could not enable IP forwarding (run as root for full functionality): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => warn!("sysctl not available: {}", e),
        }
    }

    Ok(())
}
