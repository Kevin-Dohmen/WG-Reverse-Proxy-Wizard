# VPS WireGuard Multi-Client Reverse Proxy

[![Language: Python 3](https://img.shields.io/badge/Language-Python%203-blue.svg)](https://www.python.org/)
[![VPN: WireGuard](https://img.shields.io/badge/VPN-WireGuard-red.svg)](https://www.wireguard.com/)
[![Firewall: IPTables](https://img.shields.io/badge/Firewall-IPTables%20DNAT-orange.svg)](https://netfilter.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(Debian%20%2F%20Ubuntu)-lightgrey.svg)](https://www.debian.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An interactive, zero-dependency Python management tool (`wizard.py`) for deploying a multi-tenant **WireGuard reverse proxy hub** on a Linux VPS. 

It enables self-hosters and homelabbers behind **Carrier-Grade NAT (CGNAT)** or dynamic residential IPs to expose internal services (web applications, game servers, media nodes, SSH) to the public internet securely through an inexpensive cloud VPS, with **per-client network isolation** and **automated `iptables` port forwarding**.

---

## Architecture Overview

Traditional WireGuard setups often dump all peers into a single flat subnet (`10.0.0.0/24`). This tool assigns **every client its own dedicated WireGuard interface (`wg0`, `wg1`, etc.)**, unique private subnet, and isolated port-forwarding rules.

```text
[ Public Internet Users ]
           │
           │  Traffic to VPS Public Port (e.g. 203.0.113.10:25565)
           ▼
┌──────────────────────────────────────────────────────────────────┐
│  VPS Gateway (Reverse Proxy Host)                                │
│                                                                  │
│  Public NIC: eth0                                                │
│  IPTables PREROUTING: -p tcp --dport 25565 -j DNAT               │
│                       --to-destination 10.123.8.2:25565          │
│                                                                  │
│   ┌──────────────────────────┐    ┌──────────────────────────┐   │
│   │ Interface: wg0           │    │ Interface: wg1           │   │
│   │ Subnet: 10.123.8.1/24    │    │ Subnet: 10.45.12.1/24    │   │
│   │ Client IP: 10.123.8.2    │    │ Client IP: 10.45.12.2    │   │
│   └────────────┬─────────────┘    └────────────┬─────────────┘   │
└────────────────┼───────────────────────────────┼─────────────────┘
                 │ Encrypted WireGuard Tunnel    │
                 ▼                               ▼
     ┌────────────────────────┐      ┌────────────────────────┐
     │ Homelab Minecraft VM   │      │ Offsite Web Server     │
     │ Private IP: 10.123.8.2 │      │ Private IP: 10.45.12.2 │
     │ Service: Port 25565    │      │ Service: Port 80 / 443 │
     └────────────────────────┘      └────────────────────────┘
```

### Key Highlights
- **No Manual Config Files:** The wizard generates `/etc/wireguard/wgX.conf`, handles key generation, and builds client configuration profiles automatically.
- **Live Systemd Service Management:** Automatically enables, starts, stops, or restarts `wg-quick@<interface>` systemd services as changes are made.
- **Dynamic Port Forwarding (DNAT):** Hooks directly into WireGuard's `PostUp` and `PostDown` lifecycle directives to insert clean `iptables` PREROUTING and POSTROUTING MASQUERADE rules.
- **Conflict Prevention:** Suggests unused random subnets (`10.x.x.x/24`) and high-range WireGuard listen ports (`49152–65535`).
- **Flexible Tunneling Modes:**
  - **Reverse Proxy Mode (Split Tunnel):** Only forwards traffic destined for the exposed ports and VPN subnet. Client default internet traffic does not pass through the VPS.
  - **Full Tunnel Mode:** Routes all client internet traffic (`0.0.0.0/0`) through the VPS gateway.

---

## Prerequisites

1. A cloud VPS running Linux (Debian 11/12/13, Ubuntu 20.04/22.04/24.04).
2. Root or `sudo` access.
3. Standard Linux networking packages installed:

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y wireguard wireguard-tools iptables curl python3
```

---

## Quick Start

### 1. Clone the Repository on your VPS
```bash
git clone https://github.com/Kevin-Dohmen/WG-Reverse-Proxy-Wizard.git
cd WG-Reverse-Proxy-Wizard
```

### 2. Launch the Interactive Wizard
```bash
sudo python3 wizard.py
```

The script automatically verifies root privileges, enables kernel IPv4 forwarding (`net.ipv4.ip_forward = 1`), and presents the main management menu:

```text
--- WireGuard Multi-Client Wizard ---

Menu:
1. List existing clients
2. Add a new client
3. Edit a client
4. Remove a client
5. Re-apply all configurations
6. Save and Exit
Choose an option [1]: 
```

---

## Usage Guide

### Adding a New Client (Option 2)

When adding a client, the wizard prompts you for:
1. **Client Name:** A unique descriptive identifier (e.g. `minecraft-homelab`, `jellyfin-home`).
2. **Interface Name:** The server-side WireGuard interface (`wg0`, `wg1`, etc. - auto-incremented by default).
3. **VPN Subnet:** A CIDR subnet for the client tunnel (defaults to an auto-generated, collision-free `10.x.x.1/24`). The server takes `.1` and the client takes `.2`.
4. **WireGuard Listen Port:** The public UDP port the VPS listens on for this specific tunnel (auto-selected from high range).
5. **Port Forwarding Rules (DNAT):**
   - **Protocol:** `tcp` or `udp`
   - **Public Port on Server:** The port opened on the VPS public IP.
   - **Target Port on Client:** The internal destination port where your local application listens.
6. **Full Tunnel Status:** Choose `N` for standard reverse proxy (split tunnel) or `Y` to route all client traffic through the VPS.

#### Immediate Deployment:
Upon completion, the wizard:
1. Saves `/etc/wireguard/<interface>.conf` with strict `0600` permissions.
2. Registers and restarts `systemctl start wg-quick@<interface>`.
3. Outputs the **Client Configuration File** to the terminal.

---

### Connecting Your Client Node

Copy the client configuration printed by the wizard and save it on your target client machine (e.g. `/etc/wireguard/wg0.conf` on Linux, or import into the official WireGuard GUI for Windows/macOS/Android):

```ini
[Interface]
Address = 10.123.8.2/24
PrivateKey = <CLIENT_PRIVATE_KEY>

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <YOUR_SERVER_PUBLIC_IP>:58249
AllowedIPs = 10.123.8.0/24
PersistentKeepalive = 25
```

> **Tip for NAT/Firewalled Clients:** `PersistentKeepalive = 25` is included by default to ensure residential routers and stateful firewalls keep the UDP hole-punch connection open indefinitely.

Start the client tunnel:
```bash
# On Debian/Ubuntu client:
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

---

### Managing Clients

- **List Clients (Option 1):** View all active clients, assigned interfaces, subnets, listen ports, and mapped forwarding rules.
- **Edit a Client (Option 3):** Modify rules, add new forwarded ports, or toggle full-tunnel routing live.
- **Remove a Client (Option 4):** Automatically tears down the systemd service, purges `/etc/wireguard/<interface>.conf`, cleans up iptables rules, and removes the client from `config.json`.
- **Re-Apply All (Option 5):** Re-writes and reloads all interface configurations and iptables rules across all clients (useful after network reconfigurations or system updates).

---

## Configuration File Format (`config.json`)

The state of all managed clients is persisted in `config.json`:

```json
{
    "public_interface": "eth0",
    "clients": [
        {
            "name": "minecraft-server",
            "interface_name": "wg0",
            "listen_port": 58249,
            "server_address": "10.123.8.1/24",
            "server_private_key": "<SERVER_PRIVATE_KEY>",
            "client_public_key": "<CLIENT_PUBLIC_KEY>",
            "client_allowed_ips": "10.123.8.2/32",
            "rules": [
                {
                    "comment": "Minecraft Game Server",
                    "protocol": "tcp",
                    "public_port": 25565,
                    "target_ip": "10.123.8.2",
                    "target_port": 25565
                }
            ],
            "full_tunnel": false
        }
    ]
}
```

---

## Generated Server Config Example (`/etc/wireguard/wg0.conf`)

Here is what the wizard automatically builds and applies:

```ini
# Auto-generated for client: minecraft-server
[Interface]
Address = 10.123.8.1/24
ListenPort = 58249
PrivateKey = <SERVER_PRIVATE_KEY>

# --- Core Routing & NAT (Reverse Proxy) ---
PostUp = iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE

# --- Port Forwarding Rules (DNAT) ---
# Minecraft Game Server (TCP 25565 -> 10.123.8.2:25565)
PostUp = iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25565 -j DNAT --to-destination 10.123.8.2:25565
PostDown = iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 25565 -j DNAT --to-destination 10.123.8.2:25565

[Peer]
# Client: minecraft-server
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.123.8.2/32
```

---

## Verification & Troubleshooting

### Check Live WireGuard Status
```bash
sudo wg show
```
A healthy connection shows an active endpoint IP and recent handshake:
```text
interface: wg0
  public key: +AbCd...=
  private key: (hidden)
  listening port: 58249

peer: XyZ123...=
  endpoint: 198.51.100.24:41234
  latest handshake: 14 seconds ago
  transfer: 1.42 MiB received, 4.18 MiB sent
```

### Inspect IPTables NAT Forwarding
Verify that public packets are hitting the PREROUTING chain:
```bash
sudo iptables -t nat -L PREROUTING -v -n --line-numbers
```

### Firewall (UFW) Compatibility
If UFW is enabled on your VPS, allow the public forwarding ports and the WireGuard listening port:
```bash
# Allow WireGuard tunnel handshakes
sudo ufw allow 58249/udp

# Allow the public forwarded port
sudo ufw allow 25565/tcp
```
Ensure default forward policy allows routed packets in `/etc/default/ufw`:
```ini
DEFAULT_FORWARD_POLICY="ACCEPT"
```

---

## License

This project is licensed under the [MIT License](LICENSE).
