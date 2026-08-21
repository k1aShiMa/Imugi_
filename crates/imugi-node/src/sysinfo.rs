use imugi_common::NodeInterface;

pub fn get_interfaces() -> Vec<NodeInterface> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return vec![];
    };

    let mut map: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        let cidr = match &iface.addr {
            if_addrs::IfAddr::V4(a) => {
                let prefix = u32::from(a.netmask).count_ones();
                format!("{}/{}", a.ip, prefix)
            }
            if_addrs::IfAddr::V6(a) => {
                let ip = a.ip.to_string();
                if ip.starts_with("fe80") {
                    continue;
                }
                let prefix = u128::from(a.netmask).count_ones();
                format!("{}/{}", a.ip, prefix)
            }
        };
        map.entry(iface.name).or_default().push(cidr);
    }

    map.into_iter()
        .map(|(name, addrs)| NodeInterface { name, addrs })
        .collect()
}

pub fn get_hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string()
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

pub fn get_username() -> String {
    #[cfg(unix)]
    {
        if let Ok(u) = std::env::var("USER") {
            if !u.is_empty() {
                return u;
            }
        }
        if let Ok(u) = std::env::var("LOGNAME") {
            if !u.is_empty() {
                return u;
            }
        }
        let uid = unsafe { libc::getuid() };
        lookup_passwd(uid).unwrap_or_else(|| format!("uid:{}", uid))
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
}

#[cfg(unix)]
fn lookup_passwd(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(uid) {
            return Some(parts[0].to_string());
        }
    }
    None
}
