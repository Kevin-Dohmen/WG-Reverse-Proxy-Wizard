import ipaddress
import sys

from .model import get_next_interface_name, get_random_port, get_random_subnet
from .prompts import ask, confirm, get_input
from .system import (apply_client_config, generate_keypair, get_public_ip,
                     remove_client_config)
from .validation import (SENSITIVE_PORTS, client_ip_for, validate_comment,
                         validate_interface, validate_name, validate_port,
                         validate_protocol, validate_server_address)


def select_client(config, action):
    """Ask for a client number; returns its index, or None if cancelled."""
    def parse(value):
        n = int(value) if value.isdigit() else -1
        if not 0 <= n <= len(config['clients']):
            raise ValueError(f"enter a number between 0 and {len(config['clients'])}")
        return n
    choice = ask(f"Enter the number of the client to {action} (or 0 to cancel)", "0", parse)
    if choice == 0:
        print("Cancelled.")
        return None
    return choice - 1


def prompt_for_rules(default_target_ip, used_ports):
    print("\n--- Port Forwarding Rules ---")
    rules = []
    while confirm("Add a forwarding rule?", default=True):
        print("  - New Rule -")
        comment = ask("  Description (e.g. Web Server)", "Forwarded Rule", validate_comment)
        protocol = ask("  Protocol (tcp/udp)", "tcp", validate_protocol)
        pub_port = ask("  Public Port on Server", get_random_port(used_ports), validate_port)
        if pub_port in SENSITIVE_PORTS and not confirm(
                f"  Port {pub_port} ({SENSITIVE_PORTS[pub_port]}) is used by the VPS itself; forwarding it will hijack that service. Continue?"):
            continue
        rules.append({
            "comment": comment,
            "protocol": protocol,
            "public_port": pub_port,
            "target_ip": default_target_ip,
            "target_port": ask("  Target Port on Client", pub_port, validate_port)
        })
        used_ports.append(pub_port)
        print("  > Rule added.")
    return rules


def add_new_client(config):
    print("\n--- Add New Client ---")
    client_name = ask("Enter a unique name for the client (e.g., 'minecraft-server')", validate=validate_name)
    if any(c['name'] == client_name for c in config['clients']):
        print(f"Error: A client named '{client_name}' already exists.", file=sys.stderr)
        return

    default_iface_name = get_next_interface_name(config)
    interface_name = ask("Enter the interface name for this client", default_iface_name, validate_interface)

    used_subnets = [c['server_address'] for c in config['clients']]
    server_address = ask("Enter VPN subnet for this client (CIDR)", get_random_subnet(used_subnets), validate_server_address)
    client_ip = client_ip_for(server_address)

    srv_priv, srv_pub = generate_keypair()
    cli_priv, cli_pub = generate_keypair()
    print(f"\n> Generated Server Public Key: {srv_pub}\n> Generated Client Public Key: {cli_pub}")

    used_ports = [c['listen_port'] for c in config['clients']]
    for c in config['clients']: used_ports.extend([r['public_port'] for r in c['rules']])

    client_data = {
        "name": client_name, "interface_name": interface_name,
        "listen_port": ask("WireGuard Listen Port for this client", get_random_port(used_ports), validate_port),
        "server_address": server_address, "server_private_key": srv_priv,
        "client_public_key": cli_pub, "client_allowed_ips": f"{client_ip}/32",
        "rules": prompt_for_rules(client_ip, used_ports),
        "full_tunnel": confirm("Route all client internet traffic through VPN (full tunnel)?")
    }

    if apply_client_config(client_data, config['public_interface']):
        config['clients'].append(client_data)
        print(f"\n[+] Client '{client_name}' added to config.")
        generate_and_print_client_config(client_data, srv_pub, cli_priv)


def edit_existing_client(config):
    print("\n--- Edit an Existing Client ---")
    if not list_clients(config, show_details=False): return

    index = select_client(config, "edit")
    if index is None: return
    original_client = config['clients'][index]

    while True:
        print(f"\n--- Editing '{original_client['name']}' ---")
        print("1. Edit Name")
        print("2. Edit Interface Name")
        print("3. Edit VPN Subnet")
        print("4. Edit Listen Port")
        print("5. Edit Full Tunnel Status")
        print("6. Edit Rules")
        print("7. Back to Main Menu")
        edit_choice = get_input("Choose an option", "7")

        if edit_choice == '1':
            client_name = ask("Unique name for the client", original_client['name'], validate_name)
            if client_name != original_client['name'] and any(c['name'] == client_name for c in config['clients']):
                print(f"Error: A client named '{client_name}' already exists.", file=sys.stderr)
            else:
                original_client['name'] = client_name
        elif edit_choice == '2':
            original_client['interface_name'] = ask("Interface name", original_client['interface_name'], validate_interface)
        elif edit_choice == '3':
            original_client['server_address'] = ask("VPN subnet (CIDR)", original_client['server_address'], validate_server_address)
            original_client['client_allowed_ips'] = f"{client_ip_for(original_client['server_address'])}/32"
        elif edit_choice == '4':
            original_client['listen_port'] = ask("WireGuard Listen Port", original_client['listen_port'], validate_port)
        elif edit_choice == '5':
            original_client['full_tunnel'] = confirm("Full tunnel?", default=bool(original_client.get('full_tunnel')))
        elif edit_choice == '6':
            print("\nNote: You will need to re-enter all port forwarding rules.")
            used_ports = [c['listen_port'] for c in config['clients'] if c['name'] != original_client['name']]
            for c in config['clients']:
                if c['name'] != original_client['name']: used_ports.extend([r['public_port'] for r in c['rules']])
            original_client['rules'] = prompt_for_rules(client_ip_for(original_client['server_address']), used_ports)
        elif edit_choice == '7':
            break
        else:
            print("Invalid selection.", file=sys.stderr)

        # Apply changes
        print("\n[*] Applying changes...")
        if apply_client_config(original_client, config['public_interface']):
            config['clients'][index] = original_client
            print(f"\n[+] Client '{original_client['name']}' updated successfully.")
        else:
            print(f"\n[-] Failed to apply changes for client '{original_client['name']}'.", file=sys.stderr)


def generate_and_print_client_config(client, server_pubkey, client_privkey):
    print("\n--- Client Configuration ---")
    public_ip = get_public_ip()

    allowed_ips = "0.0.0.0/0" if client.get('full_tunnel', False) else ipaddress.ip_interface(client['server_address']).network

    dns_line = ""
    if client.get('full_tunnel', False):
        dns_line = "DNS = 1.1.1.1\n"

    client_conf_content = f"""[Interface]
Address = {client['client_allowed_ips'].split('/')[0]}/{client['server_address'].split('/')[1]}
PrivateKey = {client_privkey}
{dns_line}
[Peer]
PublicKey = {server_pubkey}
Endpoint = {public_ip}:{client['listen_port']}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    print(client_conf_content.strip())
    if public_ip == "<YOUR_SERVER_PUBLIC_IP>":
        print("\n  > ACTION REQUIRED: You must manually edit the file above and replace '<YOUR_SERVER_PUBLIC_IP>' with your server's public IP address.")


def list_clients(config, show_details=True):
    print("\n--- Configured Clients ---")
    if not config['clients']:
        print("No clients configured yet.")
        return False
    for i, client in enumerate(config['clients']):
        print(f"{i+1}. {client['name']} ({client['interface_name']})")
        if show_details:
            tunnel_type = "Full Tunnel" if client.get('full_tunnel') else "Split Tunnel"
            print(f"  - Listen Port: {client['listen_port']}, VPN Subnet: {client['server_address']}")
            print(f"  - Rules: {len(client['rules'])}")
            for j, rule in enumerate(client['rules']):
                print(f"    {j+1}. {rule['protocol']}:{rule['public_port']} -> {rule['target_ip']}:{rule['target_port']}")
    return True


def remove_client(config):
    print("\n--- Remove a Client ---")
    if not list_clients(config, show_details=False): return

    index = select_client(config, "remove")
    if index is None: return
    client_to_remove = config['clients'][index]
    if confirm(f"Are you sure you want to remove '{client_to_remove['name']}'?"):
        if remove_client_config(client_to_remove):
            config['clients'].pop(index)
            print(f"\n[+] Client '{client_to_remove['name']}' removed from config.")
    else: print("Cancelled.")
