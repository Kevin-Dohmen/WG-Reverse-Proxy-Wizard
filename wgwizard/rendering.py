import ipaddress

from .validation import validate_client, validate_public_interface

# First line of every conf we write; lets us tell our files from foreign ones.
MANAGED_HEADER = "# Auto-generated for client:"


def generate_wg_config_for_client(client_data, public_interface):
    """Generates the server-side WireGuard config content for a client.

    Raises ValueError if any value is unsafe to place in a root-executed hook.
    """
    validate_public_interface(public_interface)
    validate_client(client_data)
    interface_name = client_data['interface_name']
    server_address_with_subnet = client_data['server_address']
    server_subnet = str(ipaddress.ip_interface(server_address_with_subnet).network)

    content = [
        f"{MANAGED_HEADER} {client_data['name']}",
        "[Interface]",
        f"Address = {client_data['server_address']}",
        f"ListenPort = {client_data['listen_port']}",
        f"PrivateKey = {client_data['server_private_key']}",
        ""
    ]

    # --- Routing & NAT ---
    if client_data.get('full_tunnel', False):
        content.extend([
            "# --- Full Tunnel Routing & NAT ---",
            f"PostUp = iptables -t nat -A POSTROUTING -s {server_subnet} -o {public_interface} -j MASQUERADE",
            f"PostDown = iptables -t nat -D POSTROUTING -s {server_subnet} -o {public_interface} -j MASQUERADE",
            f"PostUp = iptables -A FORWARD -i {interface_name} -o {public_interface} -j ACCEPT",
            f"PostDown = iptables -D FORWARD -i {interface_name} -o {public_interface} -j ACCEPT",
            f"PostUp = iptables -A FORWARD -i {public_interface} -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"PostDown = iptables -D FORWARD -i {public_interface} -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            ""
        ])
    else:
        # This is for the reverse proxy case where we only need basic NAT for the interface
        content.extend([
            "# --- Core Routing & NAT (Reverse Proxy) ---",
            f"PostUp = iptables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE",
            f"PostDown = iptables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE",
            ""
        ])

    # --- Port Forwarding Rules ---
    if client_data['rules']:
        content.append("# --- Port Forwarding Rules (DNAT) ---")
        for rule in client_data['rules']:
            proto, pub_port, target_ip, target_port = rule['protocol'], rule['public_port'], rule['target_ip'], rule['target_port']
            content.extend([
                f"# {rule.get('comment', 'Rule')} ({proto.upper()} {pub_port} -> {target_ip}:{target_port})",
                f"PostUp = iptables -t nat -A PREROUTING -i {public_interface} -p {proto} --dport {pub_port} -j DNAT --to-destination {target_ip}:{target_port}",
                f"PostDown = iptables -t nat -D PREROUTING -i {public_interface} -p {proto} --dport {pub_port} -j DNAT --to-destination {target_ip}:{target_port}",
            ])

    # --- Peer Configuration ---
    content.extend([
        "", "[Peer]", f"# Client: {client_data['name']}",
        f"PublicKey = {client_data['client_public_key']}",
        f"AllowedIPs = {client_data['client_allowed_ips']}"
    ])
    return "\n".join(content)
