# wg-watcher

`wg-watcher` is a unified daemon that combines two WireGuard utilities into a single program:
1. **Dynamic AllowedIPs**: Watches Linux kernel routes and dynamically updates WireGuard peers' `allowed-ips`.
2. **Keepalived**: Monitors WireGuard handshakes and resets the `listen-port` to `0` if a handshake times out.

## 1. Dynamic AllowedIPs

Intended to be used to help run BGP / OSPF over WireGuard mesh networks.

How it works:
1. Runs `ip monitor route` to watch main routing table changes.
2. After any `wg*` interface-related routing table change is detected, it runs `ip route show table main` to get full system routing info, recognize `192.168.1.0/24 via 192.168.100.10 dev wg0 proto bird` style routing records, and then run `wg set wg0 peer <peer_public_key> allowed-ips 192.168.100.10,192.168.1.0/24` to update the peer's `allowed-ips`.

Where:
- `192.168.100.10`: the peer's private `/32` IP, which should be defined statically in the `AllowedIPs = ` line of `/etc/wireguard/<interface>.conf`.
- `192.168.1.0/24 via ...`: system routing table record to route the subnet through the peer. While the `via <peer_ip>` directive itself has no effect to WireGuard, this program uses it to associate the subnet with the peer. It naturally associates the subnets assigned by BGP / OSPF routing suites (like Bird) with the correct WG peer.

It does a full routing scan & update when starting up, and when receiving a `SIGHUP` signal.

## 2. Keepalived

Monitors WireGuard interface connections to keep client sessions alive.

How it works:
1. Runs `wg show all dump` periodically (every 25 seconds) and parses the result.
2. For each specified `wg` interface that has at least one peer with "persistent keepalive" set, if the "latest handshake" is older than 180 seconds (wg session key valid time limit), it runs `wg set <interface> listen-port 0` to randomize the listen port and force a handshake attempt to reconnect.
3. It also updates the endpoint to the one defined in the static config if the current endpoint is inaccessible and different from the one in the static config. It does DNS resolving internally and round-robins through all resolved IPs
if the hostname part of wg.conf `Endpoint` is a domain.

## Usage

```
# ./wg-watcher  -h
wg-watcher: A combined WireGuard utility daemon.

Features:
1. Dynamic AllowedIPs: Watches Linux kernel routes and dynamically updates WireGuard peer's `allowed-ips`.
   Intended to be used to help run BGP / OSPF over WireGuard mesh network.
2. Keepalived: Monitors WireGuard peers' handshakes and resets `listen-port` to `0` if a
   handshake times out (older than 180s) on peers with persistent keepalive set.
   It also updates the endpoint to the one defined in the static config if the current
   endpoint is inaccessible and different from the one in the static config.


Usage: wg-watcher [OPTIONS]

Options:
  -i, --interface <INTERFACE>     Specific WireGuard interface to watch (e.g., wg0). Watches all wg* interfaces if omitted
  -c, --config-dir <CONFIG_DIR>   Directory containing WireGuard .conf files for static routing base. Set to "none" to disable parsing [default: /etc/wireguard]
  -p, --pidfile <PIDFILE>         Path to write the daemon's PID file. Set to "none" to disable [default: /var/run/wg-watcher.pid]
      --disable-endpoint-watcher  Disable tracking and applying endpoints from config for stale peers
      --disable-dns-resolution    Disable tracking failed IP addresses for DNS-resolved endpoints
  -h, --help                      Print help
  -V, --version                   Print version
```

## Build

Install Rust. For cross-compilation across architectures, you can use [cross](https://crates.io/crates/cross).

```sh
# Build Linux amd64
cross build --target x86_64-unknown-linux-musl --release

# Build Linux arm64
cross build --target aarch64-unknown-linux-musl --release

# Build Linux mipsle (soft float)
cross +nightly build --target mipsel-unknown-linux-musl \
  -Z build-std=std,core,alloc,panic_unwind \
  --release
```

## Run as system service

### Systemd service

`/etc/systemd/system/wg-watcher.service`:

```ini
[Unit]
Description=WireGuard Watcher Daemon (Dynamic AllowedIPs & Keepalived)
After=network.target

[Service]
ExecStart=/usr/bin/wg-watcher
Restart=always
User=root
# Adjust Environment if wg is not in standard path
# Environment="PATH=/usr/bin:/usr/local/bin"

[Install]
WantedBy=multi-user.target
```

Then run:
```sh
systemctl daemon-reload && systemctl enable --now wg-watcher
```

### start-stop-daemon

```sh
# start
start-stop-daemon -S -b -x wg-watcher

# stop
start-stop-daemon -K -x wg-watcher
```
