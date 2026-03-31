use clap::Parser;
#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;
#[cfg(unix)]
use signal_hook::iterator::Signals;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HANDSHAKE_TIMEOUT_SEC: u64 = 180;
const CHECK_INTERVAL_SEC: u64 = 25;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = r#"
wg-watcher: A combined WireGuard utility daemon.

Features:
1. Dynamic AllowedIPs: Watches Linux kernel routes and dynamically updates WireGuard peer's `allowed-ips`.
   Intended to be used to help run BGP / OSPF over WireGuard mesh network.
2. Keepalived: Monitors WireGuard peers' handshakes and resets `listen-port` to `0` if a
   handshake times out (older than 180s) on peers with persistent keepalive set.
   It also updates the endpoint to the one defined in the static config if the current
   endpoint is inaccessible and different from the one in the static config.
"#
)]
struct Args {
    /// Specific WireGuard interface to watch (e.g., wg0). Watches all wg* interfaces if omitted.
    #[arg(short, long)]
    interface: Option<String>,

    /// Directory containing WireGuard .conf files for static routing base.
    /// Set to "none" to disable parsing.
    #[arg(short, long, default_value = "/etc/wireguard")]
    config_dir: String,

    /// Path to write the daemon's PID file. Set to "none" to disable.
    #[arg(short, long, default_value = "/var/run/wg-watcher.pid")]
    pidfile: String,

    /// Disable tracking and applying endpoints from config for stale peers.
    #[arg(long)]
    disable_endpoint_watcher: bool,
}

#[derive(Debug, Clone)]
struct Route {
    prefix: String,
    via_ip: String,
    dev: String,
}

#[derive(Debug)]
struct PeerState {
    pubkey: String,
    anchor_ip_stripped: String,
    anchor_with_mask: String,
    current_ips: Vec<String>,
}

#[derive(Debug, Default)]
struct PeerConfig {
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
}

fn main() {
    let args = Args::parse();

    println!("Starting wg-watcher...");

    // 1. Write PID file
    if args.pidfile.to_lowercase() != "none" {
        let pid = std::process::id();
        if let Err(e) = std::fs::write(&args.pidfile, pid.to_string()) {
            eprintln!("Warning: Failed to write PID file {}: {}", args.pidfile, e);
        } else {
            println!("PID {} written to {}", pid, args.pidfile);
        }
    }

    if let Some(ref iface) = args.interface {
        println!("Watching specific interface: {}", iface);
    } else {
        println!("Watching all wg* interfaces.");
    }

    if args.config_dir.to_lowercase() == "none" {
        println!("Static config parsing disabled. Base state is anchor IP only.");
    } else {
        println!("Reading static config base from: {}", args.config_dir);
    }

    // 2. Spawn keepalived thread
    let keepalive_iface = args.interface.clone();
    let keepalive_config_dir = args.config_dir.clone();
    let disable_endpoint_watcher = args.disable_endpoint_watcher;
    thread::spawn(move || {
        println!(
            "Starting keepalived monitor: Handshakes > {}s on peers with Keepalive set. Action: 'wg set <interface> listen-port 0'",
            HANDSHAKE_TIMEOUT_SEC
        );
        loop {
            if let Err(e) = check_and_recover(&keepalive_iface, &keepalive_config_dir, disable_endpoint_watcher) {
                eprintln!("Error during keepalived check cycle: {}", e);
            }
            thread::sleep(Duration::from_secs(CHECK_INTERVAL_SEC));
        }
    });

    // 3. Run a full scan and update on program start for allowed-ips
    sync_state(&args.interface, &args.config_dir);

    // 4. Setup channels for allowed-ips triggers
    let (tx, rx) = mpsc::channel();
    let target_iface_clone = args.interface.clone();
    let tx_sighup = tx.clone();

    // 5. Spawn a thread to listen for SIGHUP
    #[cfg(unix)]
    thread::spawn(move || {
        let mut signals = Signals::new(&[SIGHUP]).expect("Failed to create signal listener");
        for _sig in signals.forever() {
            println!("\nReceived SIGHUP, scheduling full scan...");
            let _ = tx_sighup.send(());
        }
    });

    #[cfg(not(unix))]
    thread::spawn(move || {
        drop(tx_sighup); // silence unused warning
        loop { thread::sleep(Duration::from_secs(3600)); }
    });

    // 6. Spawn a thread to monitor 'ip monitor route'
    thread::spawn(move || {
        let mut child = Command::new("ip")
            .args(["monitor", "route"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start 'ip monitor route'");

        let stdout = child.stdout.take().expect("Failed to open stdout");
        let reader = BufReader::new(stdout);

        for line in reader.lines() {
            if let Ok(line) = line {
                let is_match = match &target_iface_clone {
                    Some(iface) => line.contains(&format!("dev {}", iface)),
                    None => line.contains("dev wg"),
                };

                if is_match {
                    let _ = tx.send(());
                }
            }
        }
    });

    // 7. Main loop with debounce logic for allowed-ips
    loop {
        if rx.recv().is_ok() {
            loop {
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(_) => continue,
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(_) => return,
                }
            }

            println!("\nAllowed-ips trigger detected and debounced. Synchronizing...");
            sync_state(&args.interface, &args.config_dir);
        }
    }
}

fn check_and_recover(
    target_interface: &Option<String>,
    config_dir: &str,
    disable_endpoint_watcher: bool,
) -> std::io::Result<()> {
    // 1. Run "wg show all dump"
    // Format: intf, peer_pub, psk, endpoint, allowed_ips, latest_handshake, rx, tx, persistent_keepalive
    let output = Command::new("wg")
        .arg("show")
        .arg("all")
        .arg("dump")
        .output()?;

    if !output.status.success() {
        eprintln!("keepalived: 'wg show all dump' failed");
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Use a Set to avoid resetting the same interface multiple times in one cycle
    let mut stale_interfaces = HashSet::new();
    let mut interface_configs: HashMap<String, HashMap<String, PeerConfig>> = HashMap::new();

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();

        // Basic validation of the dump line format (needs at least 9 fields)
        if fields.len() < 9 {
            continue;
        }

        let interface = fields[0];
        
        // Filter by target interface if one was specified
        if let Some(target) = target_interface {
            if interface != target {
                continue;
            }
        } else if !interface.starts_with("wg") {
            continue;
        }

        let latest_handshake_str = fields[5];
        let keepalive_str = fields[8];

        // 2. Filter: Must have PersistentKeepalive set (not "off" and not "0")
        let keepalive = keepalive_str.parse::<u64>().unwrap_or(0);
        if keepalive == 0 {
            continue;
        }

        // 3. Check Handshake Age
        let latest_handshake = latest_handshake_str.parse::<u64>().unwrap_or(now);
        let age = now.saturating_sub(latest_handshake);

        if age > HANDSHAKE_TIMEOUT_SEC {
            let peer_pub = fields[1];
            let current_endpoint = fields[3];

            if !disable_endpoint_watcher && config_dir.to_lowercase() != "none" {
                let conf_map = interface_configs.entry(interface.to_string()).or_insert_with(|| {
                    let conf_path = format!("{}/{}.conf", config_dir, interface);
                    parse_wg_conf(&conf_path)
                });

                if let Some(config) = conf_map.get(peer_pub) {
                    if let Some(config_endpoint) = &config.endpoint {
                        if config_endpoint != current_endpoint {
                            println!(
                                "[{}] Stale endpoint detected! Interface: {}, Peer: {}, Old: {}, New: {}",
                                now, interface, &peer_pub[..8], current_endpoint, config_endpoint
                            );
                            let status = Command::new("wg")
                                .args(["set", interface, "peer", peer_pub, "endpoint", config_endpoint])
                                .status();
                            if let Err(e) = status {
                                eprintln!("Failed to update endpoint for peer {}: {}", peer_pub, e);
                            }
                        }
                    }
                }
            }

            if !stale_interfaces.contains(interface) {
                println!(
                    "[{}] Stale detected! Interface: {}, Peer Keepalive: {}, Handshake Age: {}s",
                    now, interface, keepalive, age
                );
                stale_interfaces.insert(interface.to_string());
            }
        }
    }

    // 4. Action: Reset port for stale interfaces
    for interface in stale_interfaces {
        randomize_listen_port(&interface)?;
    }

    Ok(())
}

fn randomize_listen_port(interface: &str) -> std::io::Result<()> {
    println!(" -> Randomizing listen-port for '{}'...", interface);

    let status = Command::new("wg")
        .arg("set")
        .arg(interface)
        .arg("listen-port")
        .arg("0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if status.success() {
        println!(" -> Success.");
    } else {
        eprintln!(" -> Failed to set listen-port.");
    }

    Ok(())
}

fn sync_state(target_interface: &Option<String>, config_dir: &str) {
    let routes = get_bird_routes();

    let mut ifaces_to_update = HashSet::new();
    for route in &routes {
        let matches_filter = match target_interface {
            Some(iface) => &route.dev == iface,
            None => route.dev.starts_with("wg"),
        };
        if matches_filter {
            ifaces_to_update.insert(route.dev.clone());
        }
    }

    if let Some(iface) = target_interface {
        ifaces_to_update.insert(iface.clone());
    }

    for iface in ifaces_to_update {
        update_wireguard_interface(&iface, &routes, config_dir);
    }
}

fn get_bird_routes() -> Vec<Route> {
    let output = Command::new("ip")
        .args(["route", "show", "table", "main"])
        .output()
        .expect("Failed to execute 'ip route'");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut routes = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        let via_pos = parts.iter().position(|&r| r == "via");
        let dev_pos = parts.iter().position(|&r| r == "dev");

        if let (Some(v_idx), Some(d_idx)) = (via_pos, dev_pos) {
            if v_idx + 1 < parts.len() && d_idx + 1 < parts.len() {
                let mut prefix = parts[0].to_string();
                if prefix == "default" {
                    prefix = "0.0.0.0/0".to_string();
                }

                routes.push(Route {
                    prefix,
                    via_ip: parts[v_idx + 1].to_string(),
                    dev: parts[d_idx + 1].to_string(),
                });
            }
        }
    }
    routes
}

fn parse_wg_conf(path: &str) -> HashMap<String, PeerConfig> {
    let mut map: HashMap<String, PeerConfig> = HashMap::new();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: Could not open static config {}: {}", path, e);
            return map;
        }
    };

    let reader = BufReader::new(file);
    let mut current_pubkey: Option<String> = None;

    for line in reader.lines().filter_map(Result::ok) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("[Peer]") {
            current_pubkey = None;
        } else if line.to_lowercase().starts_with("publickey") {
            if let Some((_, key)) = line.split_once('=') {
                let key = key.trim().to_string();
                current_pubkey = Some(key.clone());
                map.entry(key).or_insert_with(PeerConfig::default);
            }
        } else if line.to_lowercase().starts_with("allowedips") {
            if let Some(pubkey) = &current_pubkey {
                if let Some((_, ips_str)) = line.split_once('=') {
                    let ips: Vec<String> = ips_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    if let Some(config) = map.get_mut(pubkey) {
                        config.allowed_ips.extend(ips);
                    }
                }
            }
        } else if line.to_lowercase().starts_with("endpoint") {
            if let Some(pubkey) = &current_pubkey {
                if let Some((_, endpoint_str)) = line.split_once('=') {
                    if let Some(config) = map.get_mut(pubkey) {
                        config.endpoint = Some(endpoint_str.trim().to_string());
                    }
                }
            }
        }
    }
    map
}

fn update_wireguard_interface(iface: &str, all_routes: &[Route], config_dir: &str) {
    let output = Command::new("wg")
        .args(["show", iface, "allowed-ips"])
        .output();

    if output.is_err() {
        eprintln!("Failed to run wg show for {}", iface);
        return;
    }

    let out = output.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    let mut active_peers: Vec<PeerState> = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let pubkey = parts[0].to_string();
        if parts[1] == "(none)" {
            continue;
        }

        let anchor_with_mask = parts[1].to_string();
        let anchor_ip_stripped = anchor_with_mask.split('/').next().unwrap_or("").to_string();
        let current_ips: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        active_peers.push(PeerState {
            pubkey,
            anchor_ip_stripped,
            anchor_with_mask,
            current_ips,
        });
    }

    let static_config = if config_dir.to_lowercase() != "none" {
        let conf_path = format!("{}/{}.conf", config_dir, iface);
        parse_wg_conf(&conf_path)
    } else {
        HashMap::new()
    };

    for peer in active_peers {
        let mut target_ips_set: HashSet<String> = HashSet::new();

        if let Some(static_peer) = static_config.get(&peer.pubkey) {
            for ip in &static_peer.allowed_ips {
                // Apply normalization here
                target_ips_set.insert(normalize_ip(ip));
            }
        }

        target_ips_set.insert(peer.anchor_with_mask.clone());

        for route in all_routes {
            if route.dev == iface && route.via_ip == peer.anchor_ip_stripped {
                // Apply normalization here
                target_ips_set.insert(normalize_ip(&route.prefix));
            }
        }

        let current_ips_set: HashSet<String> = peer.current_ips.iter().cloned().collect();

        if target_ips_set != current_ips_set {
            let mut remaining_ips: Vec<String> = target_ips_set
                .iter()
                .filter(|ip| **ip != peer.anchor_with_mask)
                .cloned()
                .collect();

            remaining_ips.sort();

            let mut final_ips_vec = vec![peer.anchor_with_mask.clone()];
            final_ips_vec.extend(remaining_ips);

            let joined_ips = final_ips_vec.join(",");

            println!("State change for peer {}:", &peer.pubkey[..8]);
            println!("  Old: {}", peer.current_ips.join(","));
            println!("  New: {}", joined_ips);

            let status = Command::new("wg")
                .args([
                    "set",
                    iface,
                    "peer",
                    &peer.pubkey,
                    "allowed-ips",
                    &joined_ips,
                ])
                .status();

            if let Err(e) = status {
                eprintln!("Failed to update WireGuard peer {}: {}", peer.pubkey, e);
            }
        }
    }
}

/// Normalizes an IP string to include a CIDR mask.
/// IPv4 defaults to /32, IPv6 defaults to /128.
fn normalize_ip(ip: &str) -> String {
    if ip.contains('/') {
        ip.to_string()
    } else if ip.contains(':') {
        format!("{}/128", ip)
    } else {
        format!("{}/32", ip)
    }
}
