use clap::Parser;
#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;
#[cfg(unix)]
use signal_hook::iterator::Signals;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::str::FromStr;
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
   It does DNS resolving internally and round-robins through all resolved IPs
   if the hostname part of wg.conf `Endpoint` is a domain.
3. P2P Relay Fallback: Monitors direct peer-to-peer client peer status in hub-and-spoke
   topologies. When a client peer times out (> 180s) while the server/hub peer is up,
   it dynamically removes the client's /32 from AllowedIPs to fallback traffic to the server.
   When the client peer is back online, it automatically restores the AllowedIPs.
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

    /// Disable tracking failed IP addresses for DNS-resolved endpoints.
    #[arg(long)]
    disable_dns_resolution: bool,

    /// Enable watching and rotating through multiple Endpoint definitions per peer in wg.conf.
    #[arg(long)]
    enable_multiple_endpoints: bool,

    /// Enable automatic fallback to server relay when a direct P2P client peer handshake times out (> 180s).
    #[arg(long, alias = "enable-p2p-fallback", alias = "enable-p2p-relay-fallback")]
    enable_relay_fallback: bool,

    /// Parse config file, reset all peer endpoints to their primary endpoint, and exit.
    #[arg(long)]
    reset_endpoint: bool,
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PeerConfig {
    allowed_ips: Vec<String>,
    endpoints: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct WgConfig {
    interface_addresses: Vec<String>,
    listen_port: Option<u16>,
    peers: std::collections::HashMap<String, PeerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CidrNet {
    ip: IpAddr,
    prefix_len: u8,
}

impl CidrNet {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (ip_str, mask_str) = match s.split_once('/') {
            Some((ip, mask)) => (ip, Some(mask)),
            None => (s, None),
        };

        let ip = IpAddr::from_str(ip_str).ok()?;
        let prefix_len = match mask_str {
            Some(m) => m.parse::<u8>().ok()?,
            None => match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };

        match ip {
            IpAddr::V4(_) if prefix_len > 32 => return None,
            IpAddr::V6(_) if prefix_len > 128 => return None,
            _ => {}
        }

        Some(CidrNet { ip, prefix_len })
    }

    fn to_network_cidr(&self) -> String {
        match self.ip {
            IpAddr::V4(v4) => {
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    !((1u64 << (32 - self.prefix_len)) - 1) as u32
                };
                let net_ip = Ipv4Addr::from(u32::from(v4) & mask);
                format!("{}/{}", net_ip, self.prefix_len)
            }
            IpAddr::V6(v6) => {
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    !((1u128 << (128 - self.prefix_len)) - 1)
                };
                let net_ip = Ipv6Addr::from(u128::from(v6) & mask);
                format!("{}/{}", net_ip, self.prefix_len)
            }
        }
    }

    fn contains(&self, other: &CidrNet) -> bool {
        match (self.ip, other.ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                if self.prefix_len > other.prefix_len {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    !((1u64 << (32 - self.prefix_len)) - 1) as u32
                };
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                if self.prefix_len > other.prefix_len {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    !((1u128 << (128 - self.prefix_len)) - 1)
                };
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    }

    fn is_host(&self) -> bool {
        match self.ip {
            IpAddr::V4(_) => self.prefix_len == 32,
            IpAddr::V6(_) => self.prefix_len == 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerClassification {
    // Map server_pubkey -> Vec of served network CIDRs (e.g. "192.168.110.0/24")
    server_peers: HashMap<String, Vec<CidrNet>>,
    // Map client_pubkey -> (client_anchor_ip_cidr e.g. "192.168.110.100/32", server_pubkey)
    client_peers: HashMap<String, (String, String)>,
}

fn classify_peers(config: &WgConfig) -> PeerClassification {
    let mut server_peers: HashMap<String, Vec<CidrNet>> = HashMap::new();
    let mut client_peers: HashMap<String, (String, String)> = HashMap::new();

    // 1. Calculate interface subnets if available
    let interface_subnets: Vec<CidrNet> = config
        .interface_addresses
        .iter()
        .filter_map(|addr| CidrNet::parse(addr))
        .filter_map(|cidr| CidrNet::parse(&cidr.to_network_cidr()))
        .collect();

    // 2. Identify server peers
    // A peer is recognized as a server peer if its first AllowedIP is a subnet (or matches interface subnet)
    for (pubkey, peer_cfg) in &config.peers {
        if let Some(first_ip_str) = peer_cfg.allowed_ips.first() {
            if let Some(first_cidr) = CidrNet::parse(first_ip_str) {
                let is_server = if !interface_subnets.is_empty() {
                    interface_subnets.iter().any(|if_sub| {
                        first_cidr.to_network_cidr() == if_sub.to_network_cidr()
                            || first_cidr.contains(if_sub)
                    })
                } else {
                    !first_cidr.is_host()
                };

                if is_server {
                    server_peers
                        .entry(pubkey.clone())
                        .or_default()
                        .push(first_cidr);
                }
            }
        }
    }

    // 3. Identify client peers
    // A peer is recognized as a client peer if:
    // - it is not a server peer
    // - its first AllowedIP is a host IP (/32 or /128)
    // - that host IP falls within one of the server peer subnets
    for (pubkey, peer_cfg) in &config.peers {
        if server_peers.contains_key(pubkey) {
            continue;
        }

        if let Some(first_ip_str) = peer_cfg.allowed_ips.first() {
            if let Some(client_cidr) = CidrNet::parse(first_ip_str) {
                if client_cidr.is_host() {
                    for (server_pubkey, server_subnets) in &server_peers {
                        if server_subnets.iter().any(|sub| sub.contains(&client_cidr)) {
                            let normalized_client_ip = normalize_ip(first_ip_str);
                            client_peers.insert(
                                pubkey.clone(),
                                (normalized_client_ip, server_pubkey.clone()),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    PeerClassification {
        server_peers,
        client_peers,
    }
}

#[derive(Debug, Clone)]
struct PeerDumpRecord {
    allowed_ips: String,
    latest_handshake: u64,
}

fn main() {
    let args = Args::parse();

    if args.reset_endpoint {
        reset_endpoints(&args.interface, &args.config_dir);
        return;
    }

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

    if args.enable_multiple_endpoints {
        println!("Multiple endpoints watching enabled (trying defined endpoints in reverse config order).");
    }

    if args.enable_relay_fallback {
        println!("P2P relay fallback enabled (automatically fallback to server relay when direct P2P connection times out).");
    }

    // 2. Spawn keepalived thread
    let keepalive_iface = args.interface.clone();
    let keepalive_config_dir = args.config_dir.clone();
    let disable_endpoint_watcher = args.disable_endpoint_watcher;
    let disable_dns_resolution = args.disable_dns_resolution;
    let enable_multiple_endpoints = args.enable_multiple_endpoints;
    let enable_relay_fallback = args.enable_relay_fallback;

    thread::spawn(move || {
        println!(
            "Starting keepalived monitor: Handshakes > {}s on peers with Keepalive set. Action: 'wg set <interface> listen-port 0'",
            HANDSHAKE_TIMEOUT_SEC
        );
        // Maps Peer PublicKey -> (Endpoint IP:Port -> Failure Timestamp)
        let mut failed_endpoints: HashMap<String, HashMap<String, u64>> = HashMap::new();
        loop {
            if let Err(e) = check_and_recover(
                &keepalive_iface,
                &keepalive_config_dir,
                disable_endpoint_watcher,
                disable_dns_resolution,
                enable_multiple_endpoints,
                enable_relay_fallback,
                &mut failed_endpoints,
            ) {
                eprintln!("Error during keepalived check cycle: {}", e);
            }
            thread::sleep(Duration::from_secs(CHECK_INTERVAL_SEC));
        }
    });

    // 3. Run a full scan and update on program start for allowed-ips
    sync_state(&args.interface, &args.config_dir, args.enable_relay_fallback);

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
            sync_state(&args.interface, &args.config_dir, args.enable_relay_fallback);
        }
    }
}

fn check_and_recover(
    target_interface: &Option<String>,
    config_dir: &str,
    disable_endpoint_watcher: bool,
    disable_dns_resolution: bool,
    enable_multiple_endpoints: bool,
    enable_relay_fallback: bool,
    failed_endpoints: &mut HashMap<String, HashMap<String, u64>>,
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
    let mut interface_configs: HashMap<String, WgConfig> = HashMap::new();
    let mut peer_dump_map: HashMap<(String, String), PeerDumpRecord> = HashMap::new();
    let mut observed_interfaces = HashSet::new();

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

        let peer_pub = fields[1];
        let current_endpoint = fields[3];
        let allowed_ips_str = fields[4];
        let latest_handshake_str = fields[5];
        let keepalive_str = fields[8];

        let latest_handshake = latest_handshake_str.parse::<u64>().unwrap_or(0);
        let keepalive = keepalive_str.parse::<u64>().unwrap_or(0);

        observed_interfaces.insert(interface.to_string());
        peer_dump_map.insert(
            (interface.to_string(), peer_pub.to_string()),
            PeerDumpRecord {
                allowed_ips: allowed_ips_str.to_string(),
                latest_handshake,
            },
        );

        // 2. Filter: Must have PersistentKeepalive set (not "off" and not "0")
        if keepalive == 0 {
            continue;
        }

        // 3. Check Handshake Age
        let age = if latest_handshake == 0 {
            now
        } else {
            now.saturating_sub(latest_handshake)
        };

        if age > HANDSHAKE_TIMEOUT_SEC {
            // Record this current endpoint as failed right now.
            if current_endpoint != "(none)" {
                failed_endpoints
                    .entry(peer_pub.to_string())
                    .or_default()
                    .insert(current_endpoint.to_string(), now);
            }

            if !disable_endpoint_watcher && config_dir.to_lowercase() != "none" {
                let conf = interface_configs.entry(interface.to_string()).or_insert_with(|| {
                    let conf_path = format!("{}/{}.conf", config_dir, interface);
                    parse_wg_conf(&conf_path)
                });

                if let Some(config) = conf.peers.get(peer_pub) {
                    let configured_endpoints: Vec<String> = if enable_multiple_endpoints {
                        config.endpoints.iter().rev().cloned().collect()
                    } else {
                        config.endpoints.last().cloned().into_iter().collect()
                    };

                    if !configured_endpoints.is_empty() {
                        let mut candidate_ips: Vec<String> = Vec::new();

                        for ep in &configured_endpoints {
                            if !disable_dns_resolution {
                                if let Ok(addrs) = ep.to_socket_addrs() {
                                    let addrs_vec: Vec<String> = addrs.map(|a| a.to_string()).collect();
                                    if !addrs_vec.is_empty() {
                                        candidate_ips.extend(addrs_vec);
                                    } else {
                                        candidate_ips.push(ep.clone());
                                    }
                                } else {
                                    candidate_ips.push(ep.clone());
                                }
                            } else {
                                candidate_ips.push(ep.clone());
                            }
                        }

                        if !candidate_ips.is_empty() {
                            let candidate_set: HashSet<String> = candidate_ips.iter().cloned().collect();

                            // Clean up failed IPs that are no longer part of candidate pool
                            if let Some(peer_fails) = failed_endpoints.get_mut(peer_pub) {
                                peer_fails.retain(|ip, _| candidate_set.contains(ip));
                            }

                            // Deduplicate candidate_ips while preserving first-occurrence order
                            let mut unique_candidates = Vec::new();
                            let mut seen = HashSet::new();
                            for ip in candidate_ips {
                                if seen.insert(ip.clone()) {
                                    unique_candidates.push(ip);
                                }
                            }

                            // Sort by failure time (0 = never failed). We want lowest first.
                            // Since sort_by_key is stable, elements with equal failure time (e.g. 0)
                            // retain their unique_candidates order.
                            unique_candidates.sort_by_key(|ip| {
                                failed_endpoints
                                    .get(peer_pub)
                                    .and_then(|m| m.get(ip))
                                    .copied()
                                    .unwrap_or(0)
                            });

                            let chosen_endpoint = &unique_candidates[0];

                            if chosen_endpoint != current_endpoint {
                                println!(
                                    "[{}] Stale endpoint detected! Interface: {}, Peer: {}, Old: {}, New: {}",
                                    now, interface, &peer_pub[..8.min(peer_pub.len())], current_endpoint, chosen_endpoint
                                );
                                let status = Command::new("wg")
                                    .args(["set", interface, "peer", peer_pub, "endpoint", chosen_endpoint])
                                    .status();
                                if let Err(e) = status {
                                    eprintln!("Failed to update endpoint for peer {}: {}", peer_pub, e);
                                }
                            }
                        }
                    } else {
                        // Static config no longer defines an endpoint for this peer.
                        // We shouldn't track failing DDNS IPs anymore.
                        failed_endpoints.remove(peer_pub);
                    }
                }
            }

            // Before marking as stale to reset listen-port, check if static config defines ListenPort.
            // We need to parse it if we haven't already.
            let mut skip_reset = false;
            if config_dir.to_lowercase() != "none" {
                let conf = interface_configs.entry(interface.to_string()).or_insert_with(|| {
                    let conf_path = format!("{}/{}.conf", config_dir, interface);
                    parse_wg_conf(&conf_path)
                });
                if conf.listen_port.is_some() {
                    skip_reset = true;
                }
            }

            if !skip_reset && !stale_interfaces.contains(interface) {
                println!(
                    "[{}] Stale detected! Interface: {}, Peer Keepalive: {}, Handshake Age: {}s",
                    now, interface, keepalive, age
                );
                stale_interfaces.insert(interface.to_string());
            }
        } else {
            // Handshake is recent, connection is healthy.
            if current_endpoint != "(none)" {
                if let Some(peer_fails) = failed_endpoints.get_mut(peer_pub) {
                    peer_fails.remove(current_endpoint);
                    if peer_fails.is_empty() {
                        failed_endpoints.remove(peer_pub);
                    }
                }
            }
        }
    }

    // 4. Action: Reset port for stale interfaces
    for interface in stale_interfaces {
        randomize_listen_port(&interface)?;
    }

    // 5. Action: P2P Relay Fallback management
    if enable_relay_fallback && config_dir.to_lowercase() != "none" {
        for iface in &observed_interfaces {
            let conf = interface_configs.entry(iface.clone()).or_insert_with(|| {
                let conf_path = format!("{}/{}.conf", config_dir, iface);
                parse_wg_conf(&conf_path)
            });

            let classification = classify_peers(conf);
            if classification.server_peers.is_empty() || classification.client_peers.is_empty() {
                continue;
            }

            // Check if server peer(s) are UP
            let mut server_up_map: HashMap<String, bool> = HashMap::new();
            for server_pubkey in classification.server_peers.keys() {
                let is_up = if let Some(dump_rec) = peer_dump_map.get(&(iface.clone(), server_pubkey.clone())) {
                    dump_rec.latest_handshake > 0
                        && (now.saturating_sub(dump_rec.latest_handshake) <= HANDSHAKE_TIMEOUT_SEC)
                } else {
                    false
                };
                server_up_map.insert(server_pubkey.clone(), is_up);
            }

            for (client_pubkey, (client_anchor_ip, server_pubkey)) in &classification.client_peers {
                let server_is_up = server_up_map.get(server_pubkey).copied().unwrap_or(false);

                if let Some(dump_rec) = peer_dump_map.get(&(iface.clone(), client_pubkey.clone())) {
                    let client_handshake = dump_rec.latest_handshake;
                    let client_age = if client_handshake == 0 {
                        now
                    } else {
                        now.saturating_sub(client_handshake)
                    };
                    let client_is_down = client_handshake == 0 || client_age > HANDSHAKE_TIMEOUT_SEC;

                    let current_allowed_ips: Vec<String> = if dump_rec.allowed_ips == "(none)" {
                        Vec::new()
                    } else {
                        dump_rec
                            .allowed_ips
                            .split(',')
                            .map(|s| normalize_ip(s.trim()))
                            .filter(|s| !s.is_empty())
                            .collect()
                    };

                    let normalized_anchor = normalize_ip(client_anchor_ip);
                    let contains_anchor = current_allowed_ips.contains(&normalized_anchor);

                    if client_is_down && server_is_up {
                        // Fallback condition: client is down, server is up, and client still has its AllowedIP
                        if contains_anchor {
                            let remaining_ips: Vec<String> = current_allowed_ips
                                .into_iter()
                                .filter(|ip| *ip != normalized_anchor)
                                .collect();
                            let new_ips_arg = remaining_ips.join(",");

                            let client_short = &client_pubkey[..8.min(client_pubkey.len())];
                            let server_short = &server_pubkey[..8.min(server_pubkey.len())];
                            println!(
                                "[{}] Fallback to server relay: Client peer {} is DOWN (handshake age: {}s), server {} is UP. Removing {} from allowed-ips (remaining: '{}')",
                                now, client_short, client_age, server_short, normalized_anchor, new_ips_arg
                            );

                            let status = Command::new("wg")
                                .args(["set", iface, "peer", client_pubkey, "allowed-ips", &new_ips_arg])
                                .status();

                            if let Err(e) = status {
                                eprintln!("Failed to remove allowed-ips for peer {}: {}", client_pubkey, e);
                            }
                        }
                    } else if !client_is_down {
                        // Recovery condition: client is back online, but anchor AllowedIP is missing
                        if !contains_anchor {
                            let mut restored_ips: Vec<String> = current_allowed_ips;
                            if !restored_ips.contains(&normalized_anchor) {
                                restored_ips.insert(0, normalized_anchor.clone());
                            }
                            if let Some(static_peer) = conf.peers.get(client_pubkey) {
                                for ip in &static_peer.allowed_ips {
                                    let norm = normalize_ip(ip);
                                    if !restored_ips.contains(&norm) {
                                        restored_ips.push(norm);
                                    }
                                }
                            }
                            let restored_ips_arg = restored_ips.join(",");

                            let client_short = &client_pubkey[..8.min(client_pubkey.len())];
                            println!(
                                "[{}] Restored P2P direct: Client peer {} is back ONLINE (handshake age: {}s). Restoring allowed-ips to '{}'",
                                now, client_short, client_age, restored_ips_arg
                            );

                            let status = Command::new("wg")
                                .args(["set", iface, "peer", client_pubkey, "allowed-ips", &restored_ips_arg])
                                .status();

                            if let Err(e) = status {
                                eprintln!("Failed to restore allowed-ips for peer {}: {}", client_pubkey, e);
                            }
                        }
                    }
                }
            }
        }
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

fn sync_state(target_interface: &Option<String>, config_dir: &str, enable_relay_fallback: bool) {
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
        update_wireguard_interface(&iface, &routes, config_dir, enable_relay_fallback);
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

fn parse_wg_conf(path: &str) -> WgConfig {
    let mut config = WgConfig::default();
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Warning: Could not open static config {}: {}", path, e);
            return config;
        }
    };

    let reader = BufReader::new(file);
    let mut current_pubkey: Option<String> = None;
    let mut in_interface_section = false;

    for line in reader.lines().filter_map(Result::ok) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.eq_ignore_ascii_case("[interface]") {
            in_interface_section = true;
            current_pubkey = None;
        } else if line.eq_ignore_ascii_case("[peer]") {
            in_interface_section = false;
            current_pubkey = None;
        } else if in_interface_section {
            if line.to_lowercase().starts_with("address") {
                if let Some((_, addr_str)) = line.split_once('=') {
                    let addrs: Vec<String> = addr_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    config.interface_addresses.extend(addrs);
                }
            } else if line.to_lowercase().starts_with("listenport") {
                if let Some((_, port_str)) = line.split_once('=') {
                    if let Ok(port) = port_str.trim().parse::<u16>() {
                        config.listen_port = Some(port);
                    }
                }
            }
        } else {
            // Peer section
            if line.to_lowercase().starts_with("publickey") {
                if let Some((_, key)) = line.split_once('=') {
                    let key = key.trim().to_string();
                    current_pubkey = Some(key.clone());
                    config.peers.entry(key).or_insert_with(PeerConfig::default);
                }
            } else if line.to_lowercase().starts_with("allowedips") {
                if let Some(pubkey) = &current_pubkey {
                    if let Some((_, ips_str)) = line.split_once('=') {
                        let ips: Vec<String> = ips_str
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();

                        if let Some(peer_cfg) = config.peers.get_mut(pubkey) {
                            peer_cfg.allowed_ips.extend(ips);
                        }
                    }
                }
            } else if line.to_lowercase().starts_with("endpoint") {
                if let Some(pubkey) = &current_pubkey {
                    if let Some((_, endpoint_str)) = line.split_once('=') {
                        if let Some(peer_cfg) = config.peers.get_mut(pubkey) {
                            peer_cfg.endpoints.push(endpoint_str.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    config
}

fn update_wireguard_interface(
    iface: &str,
    all_routes: &[Route],
    config_dir: &str,
    enable_relay_fallback: bool,
) {
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
        WgConfig::default()
    };

    let classification = if enable_relay_fallback {
        Some(classify_peers(&static_config))
    } else {
        None
    };

    for peer in active_peers {
        let mut target_ips_set: HashSet<String> = HashSet::new();

        let is_client_in_fallback = if let Some(ref class) = classification {
            if let Some((client_anchor_ip, _)) = class.client_peers.get(&peer.pubkey) {
                // If the client's current IPs does not contain its anchor IP, it was removed for fallback
                !peer.current_ips.iter().any(|ip| normalize_ip(ip) == normalize_ip(client_anchor_ip))
            } else {
                false
            }
        } else {
            false
        };

        if let Some(static_peer) = static_config.peers.get(&peer.pubkey) {
            for ip in &static_peer.allowed_ips {
                let norm = normalize_ip(ip);
                if is_client_in_fallback && classification.as_ref().map_or(false, |c| {
                    c.client_peers.get(&peer.pubkey).map_or(false, |(anchor, _)| normalize_ip(anchor) == norm)
                }) {
                    continue;
                }
                target_ips_set.insert(norm);
            }
        }

        if !is_client_in_fallback {
            target_ips_set.insert(peer.anchor_with_mask.clone());
        }

        for route in all_routes {
            if route.dev == iface && route.via_ip == peer.anchor_ip_stripped {
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

            let mut final_ips_vec = if !is_client_in_fallback {
                vec![peer.anchor_with_mask.clone()]
            } else {
                Vec::new()
            };
            final_ips_vec.extend(remaining_ips);

            let joined_ips = final_ips_vec.join(",");

            println!("State change for peer {}:", &peer.pubkey[..8.min(peer.pubkey.len())]);
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

fn reset_endpoints(target_interface: &Option<String>, config_dir: &str) {
    if config_dir.to_lowercase() == "none" {
        println!("Static config parsing disabled. Cannot reset endpoints.");
        return;
    }

    let mut interfaces: HashSet<String> = HashSet::new();
    if let Some(iface) = target_interface {
        interfaces.insert(iface.clone());
    } else {
        if let Ok(entries) = std::fs::read_dir(config_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("conf") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        if stem.starts_with("wg") {
                            interfaces.insert(stem.to_string());
                        }
                    }
                }
            }
        }

        if let Ok(output) = Command::new("wg").args(["show", "all", "dump"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 9 {
                        let iface = fields[0];
                        if iface.starts_with("wg") {
                            interfaces.insert(iface.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut current_endpoints: HashMap<(String, String), String> = HashMap::new();
    if let Ok(output) = Command::new("wg").args(["show", "all", "dump"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 9 {
                    let iface = fields[0].to_string();
                    let peer_pub = fields[1].to_string();
                    let endpoint = fields[3].to_string();
                    current_endpoints.insert((iface, peer_pub), endpoint);
                }
            }
        }
    }

    let mut iface_list: Vec<String> = interfaces.into_iter().collect();
    iface_list.sort();

    for iface in iface_list {
        let conf_path = format!("{}/{}.conf", config_dir, iface);
        let config = parse_wg_conf(&conf_path);

        let mut peer_pubkeys: Vec<String> = config.peers.keys().cloned().collect();
        peer_pubkeys.sort();

        for pubkey in peer_pubkeys {
            if let Some(peer_cfg) = config.peers.get(&pubkey) {
                if let Some(primary_ep) = peer_cfg.endpoints.last() {
                    let peer_short = &pubkey[..8.min(pubkey.len())];
                    if let Some(curr) = current_endpoints.get(&(iface.clone(), pubkey.clone())) {
                        println!(
                            "Resetting endpoint for interface {}, peer {}: {} -> {}",
                            iface, peer_short, curr, primary_ep
                        );
                    } else {
                        println!(
                            "Resetting endpoint for interface {}, peer {}: -> {}",
                            iface, peer_short, primary_ep
                        );
                    }

                    let status = Command::new("wg")
                        .args(["set", &iface, "peer", &pubkey, "endpoint", primary_ep])
                        .status();

                    if let Err(e) = status {
                        eprintln!(
                            "Failed to update endpoint for peer {} on interface {}: {}",
                            pubkey, iface, e
                        );
                    } else if let Ok(s) = status {
                        if !s.success() {
                            eprintln!(
                                "Command 'wg set {} peer {} endpoint {}' failed",
                                iface, pubkey, primary_ep
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_multiple_endpoints() {
        let conf_content = r#"
[Peer]
PublicKey = test_pubkey_123
Endpoint = 1.2.3.4:51820
Endpoint = 2.3.4.5:51820
"#;
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_wg.conf");
        std::fs::write(&test_file, conf_content).unwrap();

        let config = parse_wg_conf(test_file.to_str().unwrap());
        let peer = config.peers.get("test_pubkey_123").unwrap();

        assert_eq!(peer.endpoints, vec!["1.2.3.4:51820", "2.3.4.5:51820"]);

        // When multiple endpoints feature is disabled: last endpoint used
        let single_ep: Vec<String> = peer.endpoints.last().cloned().into_iter().collect();
        assert_eq!(single_ep, vec!["2.3.4.5:51820"]);

        // When multiple endpoints feature is enabled: try in reverse config order
        let multi_eps: Vec<String> = peer.endpoints.iter().rev().cloned().collect();
        assert_eq!(multi_eps, vec!["2.3.4.5:51820", "1.2.3.4:51820"]);

        std::fs::remove_file(test_file).ok();
    }

    #[test]
    fn test_reset_endpoint_flag_arg_parse() {
        let args = Args::parse_from(["wg-watcher", "--reset-endpoint"]);
        assert!(args.reset_endpoint);
    }

    #[test]
    fn test_relay_fallback_flag_arg_parse() {
        let args = Args::parse_from(["wg-watcher", "--enable-relay-fallback"]);
        assert!(args.enable_relay_fallback);

        let args2 = Args::parse_from(["wg-watcher", "--enable-p2p-fallback"]);
        assert!(args2.enable_relay_fallback);

        let args3 = Args::parse_from(["wg-watcher", "--enable-p2p-relay-fallback"]);
        assert!(args3.enable_relay_fallback);
    }

    #[test]
    fn test_cidr_net_operations() {
        let cidr = CidrNet::parse("192.168.110.50/24").unwrap();
        assert_eq!(cidr.to_network_cidr(), "192.168.110.0/24");
        assert!(!cidr.is_host());

        let host = CidrNet::parse("192.168.110.100/32").unwrap();
        assert!(host.is_host());
        assert_eq!(host.to_network_cidr(), "192.168.110.100/32");

        let net = CidrNet::parse("192.168.110.0/24").unwrap();
        assert!(net.contains(&host));
        assert!(net.contains(&cidr));

        let outside = CidrNet::parse("192.168.111.100/32").unwrap();
        assert!(!net.contains(&outside));

        // Implicit mask
        let implicit_v4 = CidrNet::parse("10.0.0.1").unwrap();
        assert_eq!(implicit_v4.prefix_len, 32);
        assert!(implicit_v4.is_host());

        // IPv6
        let v6_net = CidrNet::parse("fd00::1/64").unwrap();
        assert_eq!(v6_net.to_network_cidr(), "fd00::/64");
        let v6_host = CidrNet::parse("fd00::50/128").unwrap();
        assert!(v6_net.contains(&v6_host));
    }

    #[test]
    fn test_parse_wg_conf_and_classify_peers() {
        let conf_content = r#"
[Interface]
Address = 192.168.110.50/24
ListenPort = 51820

[peer]
# server
PublicKey = server_pubkey_11111111111111111111111111111111
AllowedIPs = 192.168.110.0/24
Endpoint = server.example.com:51820

[peer]
# bar
PublicKey = bar_client_pubkey_22222222222222222222222222222
AllowedIPs = 192.168.110.100/32
Endpoint = bar.example.com:51820

[peer]
# baz (using implicit /32)
PublicKey = baz_client_pubkey_33333333333333333333333333333
AllowedIPs = 192.168.110.101
Endpoint = baz.example.com:51820
"#;
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_wg_topology.conf");
        std::fs::write(&test_file, conf_content).unwrap();

        let config = parse_wg_conf(test_file.to_str().unwrap());
        assert_eq!(config.interface_addresses, vec!["192.168.110.50/24"]);
        assert_eq!(config.listen_port, Some(51820));
        assert_eq!(config.peers.len(), 3);

        let classification = classify_peers(&config);

        // Server peer check
        assert!(classification.server_peers.contains_key("server_pubkey_11111111111111111111111111111111"));
        assert_eq!(
            classification.server_peers.get("server_pubkey_11111111111111111111111111111111").unwrap()[0].to_network_cidr(),
            "192.168.110.0/24"
        );

        // Client bar check
        assert_eq!(
            classification.client_peers.get("bar_client_pubkey_22222222222222222222222222222"),
            Some(&(
                "192.168.110.100/32".to_string(),
                "server_pubkey_11111111111111111111111111111111".to_string()
            ))
        );

        // Client baz check (implicit /32 normalized)
        assert_eq!(
            classification.client_peers.get("baz_client_pubkey_33333333333333333333333333333"),
            Some(&(
                "192.168.110.101/32".to_string(),
                "server_pubkey_11111111111111111111111111111111".to_string()
            ))
        );

        std::fs::remove_file(test_file).ok();
    }
}

