import ipaddress
import sys

from .model import get_next_interface_name, get_random_port, get_random_subnet
from .prompts import get_input
from .system import (apply_client_config, generate_keypair, get_public_ip,
                     remove_client_config)


def prompt_for_rules(default_target_ip, used_ports):
    print("\n--- Port Forwarding Rules ---")
    rules = []
    while True:
        if not get_input("Add a forwarding rule? [Y/n]", "y").lower() in ["y", "yes"]: break
        print("  - New Rule -")
        rules.append({
            "comment": get_input("  Description (e.g. Web Server)", "Forwarded Rule"),
            "protocol": get_input("  Protocol (tcp/udp)", "tcp"),
            "public_port": int(pub_port := get_input("  Public Port on Server", get_random_port(used_ports))),
            "target_ip": default_target_ip,
            "target_port": int(get_input(f"  Target Port on Client", str(pub_port)))
        })
        used_ports.append(int(pub_port))
        print("  > Rule added.")
    return rules


def add_new_client(config):
    print("\n--- Add New Client ---")
    client_name = get_input("Enter a unique name for the client (e.g., 'minecraft-server')")
    if any(c['name'] == client_name for c in config['clients']):
        print(f"Error: A client named '{client_name}' already exists.", file=sys.stderr)
        return

    default_iface_name = get_next_interface_name(config)
    interface_name = get_input("Enter the interface name for this client", default_iface_name)

    used_subnets = [c['server_address'] for c in config['clients']]
    server_address = get_input("Enter VPN subnet for this client (CIDR)", get_random_subnet(used_subnets))

    try:
        server_ip_obj = ipaddress.ip_interface(server_address).ip
        client_ip = str(server_ip_obj + 1)
    except ValueError as e: print(f"Error: Invalid CIDR address: {e}", file=sys.stderr); return

    srv_priv, srv_pub = generate_keypair()
    cli_priv, cli_pub = generate_keypair()
    print(f"\n> Generated Server Public Key: {srv_pub}\n> Generated Client Public Key: {cli_pub}")

    used_ports = [c['listen_port'] for c in config['clients']]
    for c in config['clients']: used_ports.extend([r['public_port'] for r in c['rules']])

    client_data = {
        "name": client_name, "interface_name": interface_name,
        "listen_port": int(get_input("WireGuard Listen Port for this client", get_random_port(used_ports))),
        "server_address": server_address, "server_private_key": srv_priv,
        "client_public_key": cli_pub, "client_allowed_ips": f"{client_ip}/32",
        "rules": prompt_for_rules(client_ip, used_ports),
        "full_tunnel": get_input("Route all client internet traffic through VPN (full tunnel)? [y/N]", "n").lower() in ["y", "yes"]
    }

    if apply_client_config(client_data, config['public_interface']):
        config['clients'].append(client_data)
        print(f"\n[+] Client '{client_name}' added to config.")
        generate_and_print_client_config(client_data, srv_pub, cli_priv)


def edit_existing_client(config):
    print("\n--- Edit an Existing Client ---")
    if not list_clients(config, show_details=False): return

    try:
        choice = int(get_input("Enter the number of the client to edit (or 0 to cancel)", "0"))
        if choice == 0 or choice > len(config['clients']):
            print("Cancelled.")
            return

        original_client = config['clients'][choice - 1]

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
                client_name = get_input("Unique name for the client", original_client['name'])
                if client_name != original_client['name'] and any(c['name'] == client_name for c in config['clients']):
                    print(f"Error: A client named '{client_name}' already exists.", file=sys.stderr)
                else:
                    original_client['name'] = client_name
            elif edit_choice == '2':
                original_client['interface_name'] = get_input("Interface name", original_client['interface_name'])
            elif edit_choice == '3':
                original_client['server_address'] = get_input("VPN subnet (CIDR)", original_client['server_address'])
                try:
                    server_ip_obj = ipaddress.ip_interface(original_client['server_address']).ip
                    original_client['client_allowed_ips'] = f"{str(server_ip_obj + 1)}/32"
                except ValueError as e:
                    print(f"Error: Invalid CIDR address: {e}", file=sys.stderr)
            elif edit_choice == '4':
                used_ports = [c['listen_port'] for c in config['clients'] if c['name'] != original_client['name']]
                for c in config['clients']:
                    if c['name'] != original_client['name']: used_ports.extend([r['public_port'] for r in c['rules']])
                original_client['listen_port'] = int(get_input("WireGuard Listen Port", original_client['listen_port']))
            elif edit_choice == '5':
                original_client['full_tunnel'] = get_input("Full tunnel? [y/N]", 'y' if original_client.get('full_tunnel') else 'n').lower() in ["y", "yes"]
            elif edit_choice == '6':
                print("\nNote: You will need to re-enter all port forwarding rules.")
                used_ports = [c['listen_port'] for c in config['clients'] if c['name'] != original_client['name']]
                for c in config['clients']:
                    if c['name'] != original_client['name']: used_ports.extend([r['public_port'] for r in c['rules']])
                server_ip_obj = ipaddress.ip_interface(original_client['server_address']).ip
                client_ip = str(server_ip_obj + 1)
                original_client['rules'] = prompt_for_rules(client_ip, used_ports)
            elif edit_choice == '7':
                break
            else:
                print("Invalid selection.", file=sys.stderr)

            # Apply changes
            print("\n[*] Applying changes...")
            if apply_client_config(original_client, config['public_interface']):
                config['clients'][choice - 1] = original_client
                print(f"\n[+] Client '{original_client['name']}' updated successfully.")
            else:
                print(f"\n[-] Failed to apply changes for client '{original_client['name']}'.", file=sys.stderr)

    except (ValueError, IndexError):
        print("Invalid selection.", file=sys.stderr)


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

    try:
        choice = int(get_input("Enter the number of the client to remove (or 0 to cancel)", "0"))
        if choice == 0 or choice > len(config['clients']): print("Cancelled."); return

        client_to_remove = config['clients'][choice - 1]
        confirm = get_input(f"Are you sure you want to remove '{client_to_remove['name']}'? [y/N]", "n")
        if confirm.lower() in ["y", "yes"]:
            if remove_client_config(client_to_remove):
                config['clients'].pop(choice - 1)
                print(f"\n[+] Client '{client_to_remove['name']}' removed from config.")
        else: print("Cancelled.")
    except (ValueError, IndexError):
        print("Invalid selection.", file=sys.stderr)
