/// Simple interactive CLI UI for the proxy.
///
/// Runs in its own task, reads stdin commands, prints session info.
/// Keeps it terminal-friendly for HTB — no TUI deps needed.

use crate::session::{list_sessions, SessionMap, SessionState};
use crate::tun::TunDevice;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

pub async fn run_ui(sessions: SessionMap, tun: Arc<tokio::sync::Mutex<TunDevice>>) {
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    print_banner();
    print_help();

    loop {
        print!("\x1b[1;32mtunneler\x1b[0m > ");
        // Flush stdout
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break, // EOF
            Err(_) => break,
        };

        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "sessions" | "ls" => {
                cmd_sessions(&sessions).await;
            }
            "routes" => {
                cmd_routes(&tun).await;
            }
            "add-route" => {
                if parts.len() < 2 {
                    eprintln!("Usage: add-route <CIDR>");
                } else {
                    cmd_add_route(&tun, parts[1]).await;
                }
            }
            "del-route" => {
                if parts.len() < 2 {
                    eprintln!("Usage: del-route <CIDR>");
                } else {
                    cmd_del_route(&tun, parts[1]).await;
                }
            }
            "help" | "?" => print_help(),
            "quit" | "exit" | "q" => {
                println!("Shutting down...");
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown command: '{}'. Type 'help' for commands.", other);
            }
        }
    }
}

async fn cmd_sessions(sessions: &SessionMap) {
    let list = list_sessions(sessions).await;
    if list.is_empty() {
        println!("  No agents connected.");
        return;
    }
    println!(
        "\n  {:<38} {:<20} {:<15} {:<10}",
        "Session ID", "Hostname", "User", "State"
    );
    println!("  {}", "-".repeat(90));
    for s in &list {
        let state_str = match s.state {
            SessionState::Connected => "\x1b[33mCONNECTED\x1b[0m",
            SessionState::Active => "\x1b[32mACTIVE\x1b[0m",
            SessionState::Dead => "\x1b[31mDEAD\x1b[0m",
        };
        println!(
            "  {:<38} {:<20} {:<15} {}",
            s.id, s.hostname, s.username, state_str
        );
        for iface in &s.interfaces {
            println!(
                "    \x1b[90m{}: {}\x1b[0m",
                iface.name,
                iface.addrs.join(", ")
            );
        }
    }
    println!();
}

async fn cmd_routes(tun: &Arc<tokio::sync::Mutex<TunDevice>>) {
    let dev = tun.lock().await;
    // Read current routes from ip route
    let out = std::process::Command::new("ip")
        .args(["route", "show", "dev", &dev.name])
        .output();
    match out {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.trim().is_empty() {
                println!("  No routes via {}", dev.name);
            } else {
                println!("\n  Routes via {}:", dev.name);
                for line in s.lines() {
                    println!("    {}", line);
                }
                println!();
            }
        }
        Err(e) => eprintln!("  Failed to list routes: {}", e),
    }
}

async fn cmd_add_route(tun: &Arc<tokio::sync::Mutex<TunDevice>>, subnet: &str) {
    let dev = tun.lock().await;
    match dev.add_route(subnet) {
        Ok(_) => println!("  \x1b[32m✓\x1b[0m Route {} added", subnet),
        Err(e) => eprintln!("  \x1b[31m✗\x1b[0m Failed: {}", e),
    }
}

async fn cmd_del_route(tun: &Arc<tokio::sync::Mutex<TunDevice>>, subnet: &str) {
    let dev = tun.lock().await;
    dev.del_route(subnet);
    println!("  \x1b[32m✓\x1b[0m Route {} removed", subnet);
}

fn print_banner() {
    println!(
        r#"
  ╔════════════════════════════════════════╗
  ║        tunneler-proxy  v0.1.0          ║
  ║    Linux TUN/TLS pivoting proxy        ║
  ╚════════════════════════════════════════╝
"#
    );
}

fn print_help() {
    println!(
        r#"  Commands:
    sessions / ls          List connected agents
    routes                 Show routes via TUN interface
    add-route <CIDR>       Add route to target subnet  (e.g. 192.168.2.0/24)
    del-route <CIDR>       Remove a route
    help / ?               This message
    quit / exit            Shutdown proxy
"#
    );
}
