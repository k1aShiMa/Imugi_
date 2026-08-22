/// System information gathering — Windows node.
///
/// Uses windows-sys for WinAPI calls:
///   - GetAdaptersAddresses → network interfaces + CIDR addrs
///   - GetComputerNameExW  → hostname
///   - GetUserNameW        → current username
 
use imugi_common::NodeInterface;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX,
        IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
    System::SystemInformation::{GetComputerNameExW, ComputerNameDnsHostname},
    System::WindowsProgramming::GetUserNameW,
};
 
pub fn get_interfaces() -> Vec<NodeInterface> {
    let mut out = Vec::new();
 
    unsafe {
        // First call: get required buffer size
        let mut buf_len: u32 = 0;
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut buf_len,
        );
 
        if buf_len == 0 { return out; }
 
        let mut buf = vec![0u8; buf_len as usize];
        let ret = GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        );
 
        if ret != 0 { return out; }
 
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = &*adapter;
 
            let name = wide_to_string(a.FriendlyName);
 
            // Skip loopback (IF_TYPE_SOFTWARE_LOOPBACK = 24)
            if a.IfType == 24 {
                adapter = a.Next;
                continue;
            }
 
            let mut addrs: Vec<String> = Vec::new();
 
            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                let unicast = &*ua;
                let sa = unicast.Address.lpSockaddr;
 
                if sa.is_null() {
                    ua = unicast.Next;
                    continue;
                }
 
                let family = (*sa).sa_family;
 
                if family == AF_INET as u16 {
                    let sin = sa as *const SOCKADDR_IN;
                    let b = (*sin).sin_addr.S_un.S_un_b;
                    let ip = Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4);
                    addrs.push(format!("{}/{}", ip, unicast.OnLinkPrefixLength));
                } else if family == AF_INET6 as u16 {
                    let sin6 = sa as *const SOCKADDR_IN6;
                    let ip = Ipv6Addr::from((*sin6).sin6_addr.u.Byte);
                    if !ip.to_string().starts_with("fe80") {
                        addrs.push(format!("{}/{}", ip, unicast.OnLinkPrefixLength));
                    }
                }
 
                ua = unicast.Next;
            }
 
            if !addrs.is_empty() {
                out.push(NodeInterface { name, addrs });
            }
 
            adapter = a.Next;
        }
    }
 
    out
}
 
pub fn get_hostname() -> String {
    if let Ok(h) = std::env::var("COMPUTERNAME") {
        if !h.is_empty() { return h; }
    }
    unsafe {
        let mut len: u32 = 256;
        let mut buf = vec![0u16; len as usize];
        if GetComputerNameExW(ComputerNameDnsHostname, buf.as_mut_ptr(), &mut len) != 0 {
            return String::from_utf16_lossy(&buf[..len as usize]);
        }
    }
    "unknown".to_string()
}
 
pub fn get_username() -> String {
    if let Ok(u) = std::env::var("USERNAME") {
        if !u.is_empty() { return u; }
    }
    unsafe {
        let mut len: u32 = 256;
        let mut buf = vec![0u16; len as usize];
        if GetUserNameW(buf.as_mut_ptr(), &mut len) != 0 {
            return String::from_utf16_lossy(&buf[..len.saturating_sub(1) as usize]);
        }
    }
    "unknown".to_string()
}
 
fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() { return String::new(); }
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 { len += 1; }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}