/// System information gathering for the Linux node.
/// Enumerates network interfaces and pulls hostname/username.

use imugi_common::NodeInterface;
use std::net::{IpAddr, Ipv4Addr};

/// Collect all non-loopback interfaces with their CIDR addresses.
pub fn get_interfaces() -> Vec<NodeInterface> {
    let mut out = Vec::new();

    // Read interfaces from /proc/net/if_inet6 and /proc/net/fib_trie
    // Simpler: use getifaddrs via libc
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }

        let mut seen: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        let mut ifa = ifap;
        while !ifa.is_null() {
            let name = std::ffi::CStr::from_ptr((*ifa).ifa_name)
                .to_string_lossy()
                .into_owned();

            // Skip loopback
            if name == "lo" {
                ifa = (*ifa).ifa_next;
                continue;
            }

            if !(*ifa).ifa_addr.is_null() {
                let family = (*(*ifa).ifa_addr).sa_family as i32;

                if family == libc::AF_INET {
                    let sin = (*ifa).ifa_addr as *const libc::sockaddr_in;
                    let addr = Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));

                    // Get prefix length from netmask
                    let prefix = if !(*ifa).ifa_netmask.is_null() {
                        let mask = (*ifa).ifa_netmask as *const libc::sockaddr_in;
                        let mask_u32 = u32::from_be((*mask).sin_addr.s_addr);
                        mask_u32.count_ones() as u8
                    } else {
                        32
                    };

                    let cidr = format!("{}/{}", addr, prefix);
                    seen.entry(name).or_default().push(cidr);
                } else if family == libc::AF_INET6 {
                    let sin6 = (*ifa).ifa_addr as *const libc::sockaddr_in6;
                    let addr = IpAddr::V6(std::net::Ipv6Addr::from((*sin6).sin6_addr.s6_addr));
                    // Skip link-local fe80::
                    if !addr.to_string().starts_with("fe80") {
                        seen.entry(name).or_default().push(format!("{}/128", addr));
                    }
                }
            }

            ifa = (*ifa).ifa_next;
        }

        libc::freeifaddrs(ifap);

        for (name, addrs) in seen {
            out.push(NodeInterface { name, addrs });
        }
    }

    out
}

pub fn get_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

pub fn get_username() -> String {
    // Try $USER env, fall back to reading /proc/self/status for Uid then /etc/passwd
    if let Ok(u) = std::env::var("USER") {
        if !u.is_empty() { return u; }
    }
    if let Ok(u) = std::env::var("LOGNAME") {
        if !u.is_empty() { return u; }
    }
    // Read UID from /proc/self/status, look up in /etc/passwd
    let uid = get_uid();
    lookup_passwd(uid).unwrap_or_else(|| format!("uid:{}", uid))
}

fn get_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn lookup_passwd(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if parts[2].parse::<u32>().ok() == Some(uid) {
                return Some(parts[0].to_string());
            }
        }
    }
    None
}
