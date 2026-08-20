/// TUN interface management using the `tun` 0.6 crate.
///
/// Creates a tun interface, assigns it an address, brings it up,
/// and provides async read/write for raw IP packets.
/// Routes to target subnets are managed via `ip route` shell calls.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

pub const TUN_MTU: usize = 1500;

/// Wraps an async TUN device with convenient read/write methods.
pub struct TunDevice {
    pub name: String,
    inner: tun::AsyncDevice,
}

impl TunDevice {
    /// Create and bring up the TUN interface.
    pub fn new(name: &str, addr: &str, netmask: &str) -> Result<Self> {
        let addr: Ipv4Addr = addr.parse().context("Invalid TUN addr")?;
        let netmask: Ipv4Addr = netmask.parse().context("Invalid TUN netmask")?;

        let mut config = tun::Configuration::default();
        config
            .name(name)
            .address(addr)
            .netmask(netmask)
            .mtu(TUN_MTU as i32)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|p| {
            p.packet_information(false); // raw IP frames, no PI prefix
        });

        let dev = tun::create_as_async(&config)
            .context("Failed to create TUN device — are you root?")?;

        let dev_name = name.to_owned();
        info!("TUN interface '{}' up at {}", dev_name, addr);

        Ok(TunDevice {
            name: dev_name,
            inner: dev,
        })
    }

    /// Read one IP packet from the TUN interface.
    pub async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; TUN_MTU + 4];
        let n = self.inner.read(&mut buf).await.context("TUN read failed")?;
        if n == 0 {
            bail!("TUN device EOF");
        }
        buf.truncate(n);
        Ok(buf)
    }

    /// Write one IP packet into the TUN interface.
    pub async fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        self.inner.write_all(pkt).await.context("TUN write failed")?;
        Ok(())
    }

    /// Add a route pointing at this TUN interface.
    /// e.g. "10.10.110.0/24" → `ip route add 10.10.110.0/24 dev tunneler0`
    pub fn add_route(&self, subnet: &str) -> Result<()> {
        info!("Adding route {} via {}", subnet, self.name);
        let out = Command::new("ip")
            .args(["route", "add", subnet, "dev", &self.name])
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

    /// Remove a previously added route.
    pub fn del_route(&self, subnet: &str) {
        let _ = Command::new("ip")
            .args(["route", "del", subnet, "dev", &self.name])
            .output();
        info!("Removed route {}", subnet);
    }
}

/// Enable IP forwarding (required for packet routing).
pub fn enable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("Failed to enable IP forwarding — are you root?")?;
    info!("IP forwarding enabled");
    Ok(())
}
