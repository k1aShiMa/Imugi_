# Imugi_

A cross-platform network tunneling and pivoting tool written in Rust, designed for penetration testing and red team operations. Imugi_ provides encrypted tunnel infrastructure between agents and operators, enabling seamless network pivoting through compromised hosts.

>  **Disclaimer:** Imugi_ is intended strictly for authorized penetration testing, red team engagements, and controlled lab environments (e.g. HackTheBox, TryHackMe, CRTE/CRTO labs). Do not use against systems you do not have explicit written permission to test. The author assumes no responsibility for misuse.

---

## Features

- **Bidirectional tunneling** route traffic through a compromised pivot host transparently
- **Cross-platform** single codebase compiled natively for Linux and Windows
- **Written in Rust** low overhead, no GC pauses, minimal runtime footprint
- **Encrypted transport** traffic between agent and operator is encrypted in transit
- **Low signature profile** no dependency on common C2 frameworks or detectable runtimes
- **Async I/O** built on Tokio for efficient concurrent connection handling
- **TUN/TAP interface support** operator-side interface for full network-layer routing (Linux)
- **WinDivert / raw socket support** Windows pivot agent traffic capture

---

## Architecture

```
[ Operator Machine ]                [ Pivot Host (Compromised) ]          [ Target Network ]
                                                                        
  imugi-proxy ◄──── encrypted ────► imugi-agent ◄───────────────────────► 10.10.10.0/24
  (TUN iface)        tunnel           (implant)       raw socket / TAP
  
  Routes all traffic destined for the target subnet through the pivot automatically.
```

**Components:**

| Binary        | Role                                                             | Platform        |
| ------------- | ---------------------------------------------------------------- | --------------- |
| `imugi-proxy` | Operator-side listener, creates TUN interface, handles routing   | Linux           |
| `imugi-agent` | Runs on the pivot host, connects back to proxy, forwards traffic | Linux / Windows |

---

## Installation

### Prebuilt Binaries

Download the latest release from the [Releases](#) page:

```
imugi-proxy       # Linux x86_64 operator binary
imugi-agent-linux # Linux x86_64 agent
imugi-agent.exe   # Windows x86_64 agent (cross-compiled)
```

### Build from Source

**Prerequisites:**

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows cross-compilation target
rustup target add x86_64-pc-windows-gnu

# Cross-compilation toolchain (Debian/Ubuntu)
sudo apt install mingw-w64
```

**Build:**

```bash
git clone https://github.com/k1aShiMa/Imugi_
cd Imugi_

# Linux binaries
# Add the musl target
rustup target add x86_64-unknown-linux-musl

# On Debian/Ubuntu you need musl-tools
sudo apt install musl-tools

# Compile against musl instead of glibc
cargo build --release -p imugi-node --target x86_64-unknown-linux-musl

# Windows agent (cross-compiled from Linux)
cargo build --release -p imugi-node --target x86_64-pc-windows-gnu
```

Output binaries will be in `target/release/` and `target/x86_64-pc-windows-gnu/release/`.

---

## Usage

### 1. Start the proxy on your operator machine

```bash
# Quick lab use, default 4444 port execution
sudo ./imugi-proxy

# Help menu
sudo ./imugi-proxy -h

# Custom port usage
sudo ./imugi-proxy --listen 0.0.0.0:443
```

```
[*] Imugi_ proxy listening on 0.0.0.0:4444
[*] TUN interface 'imugi0' created
[*] Waiting for agent connection...
```

### 2. Transfer and run the agent on the pivot host

**Linux pivot:**
```bash
# Quick lab use — no pinning
./imugi-node --proxy $YOUR_IP:4444 --accept-any-cert

# With retry (survives connection drops)
./imugi-node --proxy $YOUR_IP:4444 --accept-any-cert --retry 15

# With cert pinning (fingerprint from proxy startup output)
./imugi-node --proxy $YOUR_IP:4444 --fingerprint $FINGERPRINT
```

**Windows pivot:**
```cmd
imugi-agent.exe --proxy <YOUR_IP>:4444
```

```bash
nmap -sV 172.16.0.10
evil-winrm -i 172.16.0.10 -u Administrator -p 'Password123'
```

---

## Options

### `imugi-proxy`

| Flag       | Short | Description                                                                | Default       |
| ---------- | ----- | -------------------------------------------------------------------------- | ------------- |
| --listen   | `-l`  | Address and port to listen for agent connections                           | 0.0.0.0:4444  |
| --tun-name | -     | TUN interface name to create                                               | imugi0        |
| --tun-addr | -     | IP address assigned to the TUN interface                                   | 240.0.0.1     |
| --tun-mask | -     | Subnet mask for the TUN interface                                          | 255.255.255.0 |
| --route    | `-r`  | Route add at startup, repeatable (`-r 10.10.110.0/24 -r 192.168.110.0/24`) | None          |
| --cert     | -     | Path to TLS certificate file (PEM)                                         | None          |
| --key      | -     | Path to TLS private key (PEM)                                              | None          |
| --log      | -     | Log level (right now just info)                                            | `info`          |
| --help     | `-h`  |                                                                            | -             |
| --version  | `-V`  |                                                                            | -             |

### `imugi-node`

| Flag               | Short | Description                                                            | Default  |
| ------------------ | ----- | ---------------------------------------------------------------------- | -------- |
| --proxy $Addr      | `-p`    | Proxy address to connect back to (`ip:port`)                           | Required |
| --retry            | -     | Retry interval on disconnect in seconds (0 = no retry)                 | 10       |
| --accept-any-cert  | -     | Accept any TLS certificate, for lab use, no cert pinning               | Off      |
| --fingerprint $HEX | -     | Proxy cert SHA fingerprint for pinning (hex from proxy startup output) | None     |
| --log              | -     | Log level (right now just info)                                        | `info`   |
| --help             | `-h`    | Print  help                                                            | -        |
| --version          | `-V`    | Print version                                                          | -        |

---

## Tested Environments

| Environment | Status |
|---|---|
| HTB Linux labs (pivot) | In-prog |
| Parrot Linux (operator) | Successful |
| Windows 10/11 (agent) | In-prog |
| Windows Server 2019/2022 (agent) | In-prog |

---

## Roadmap

- [X] Write the file to disk on Linux environment
- [ ] In-memory agent execution (reflective loading)
- [ ] DLL sideloading delivery variant
- [ ] Compile-time string encryption
- [ ] Mesh-based multi-hop tunneling
- [ ] HTTPS/WebSocket transport option
- [ ] Config file support
- [ ] Multiplexed sessions (multiple agents, single proxy)

---

## Changelog

### 2026-08-20 — Build fixes & cross-platform support

**Compile fixes**

- `imugi-proxy/Cargo.toml`: added all missing dependencies (`rustls`, `tokio-rustls`, `rustls-pemfile`, `clap`, `tracing`, `tracing-subscriber`, `serde`, `serde_json`, `dashmap`, `uuid`, `libc`, `bytes`, `futures`, `rcgen`, `imugi-common`)
- Created `crates/imugi-proxy/src/protocol.rs`: re-exports `imugi-common` wire types under the names the proxy codebase uses (`AgentHello` → `NodeHello`, `AgentInterface` → `NodeInterface`, `AgentMessage` → `NodeMsg`, `ProxyCommand` → `ProxyCmd`)
- `imugi-node/src/forward.rs`: removed `sin_len` from `sockaddr_in` initializer (macOS-only field absent on Linux)

**Windows + Linux support (node)**

- `forward.rs` — split into two platform implementations behind `#[cfg]` gates:
  - *Linux*: existing `AF_PACKET` raw socket for RX (L2 capture), `IPPROTO_RAW` + `IP_HDRINCL` for TX; uses `tokio::io::unix::AsyncFd` for non-blocking reads
  - *Windows*: `WSASocket` with `IPPROTO_IP` + `WSAIoctl(SIO_RCVALL)` for promiscuous IP capture (no L2 header to strip), `IPPROTO_RAW` + `IP_HDRINCL` for TX; recv runs in a dedicated blocking thread feeding a tokio channel
- `sysinfo.rs` — replaced `libc::getifaddrs` (Linux-only) with the `if-addrs` crate (cross-platform interface enumeration); hostname/username now use `/proc` + passwd on Linux and `COMPUTERNAME`/`USERNAME` env vars on Windows
- `connect.rs` — replaced hardcoded `"linux"` OS string with `std::env::consts::OS`
- `libc` moved to `[target.'cfg(unix)'.dependencies]`; `windows-sys 0.52` added as a Windows-only dependency

**Windows + Linux support (proxy)**

- `tun/mod.rs` — `TunDevice` creation and read/write gated with `#[cfg(unix)]`/`#[cfg(windows)]`; Windows path returns a clear error directing users to run the proxy on Linux
- Routing commands: `ip route add/del` on Linux/macOS, `route ADD/DELETE` on Windows
- IP forwarding: `/proc/sys/net/ipv4/ip_forward` on Linux, `sysctl` on macOS, `netsh interface ipv4 set global forwarding=enabled` on Windows
- `tun` crate dependency moved to `[target.'cfg(unix)'.dependencies]` (crate has no Windows support)
- `main.rs` — `libc::geteuid()` root check gated to `#[cfg(unix)]`

---

## Comparison to ligolo-ng

Imugi_ draws heavy inspiration from [ligolo-ng](https://github.com/nicocha30/ligolo-ng). Key differences:

| | ligolo-ng | Imugi_ |
|---|---|---|
| Language | Go | Rust |
| Runtime | Go runtime (detectable) | No runtime |
| Binary size | Larger | Smaller |
| AV profile | Commonly signatured | Lower baseline detection |
| Mesh tunneling | Yes | Planned |
| Focus | Feature-complete | Stealth + evasion |

---

## Authors

**k1aShiMa & GohanFX** *tools signed with an underscore*

Part of the `Kitsune_` tool family:
- `Kitsune_` C2 framework
- `Imugi_` tunneling / pivoting

---

## License

Copyright (C) 2026 k1aShiMa and GohanFX
This program is licensed under the GNU General Public License v3.
See LICENSE for details.
