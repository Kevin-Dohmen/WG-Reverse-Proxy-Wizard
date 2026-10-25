import copy
import ipaddress
import sys

from .host import generate_keypair, get_public_ip, local_ipv4_networks
from .model import get_next_interface_name, get_random_port, get_random_subnet
from .prompts import ask, confirm, get_input
from .service import apply_client_config, ensure_interface_unused, remove_client_config
from .validation import (SENSITIVE_PORTS, check_interface_free, check_listen_port_free,
                         check_name_free, check_public_port_free, check_subnet_free,
                         client_ip_for, validate_comment, validate_interface,
                         validate_name, validate_port, validate_protocol,
                         validate_server_address)


# --- Validators that know about the rest of the config -------------------------

def name_validator(others):
    def check(value):
        name = validate_name(value)
        check_name_free(others, name)
        return name
    return check


def interface_validator(others, current=None):
    def check(value):
        iface = validate_interface(value)
        if iface != current:  # an unchanged name is ours already
            check_interface_free(others, iface)
            ensure_interface_unused(iface)
        return iface
    return check


def subnet_validator(others, managed_interfaces):
    host_networks = local_ipv4_networks(skip_interfaces=managed_interfaces)
    def check(value):
        address = validate_server_address(value)
        check_subnet_free(others, address, host_networks)
        return address
    return check, host_networks


def listen_port_validator(others, rules=()):
    def check(value):
        port = validate_port(value)
        check_listen_port_free(others, port, rules)
        return port
    return check


def used_ports(others, rules=(), listen_port=None):
    ports = {c['listen_port'] for c in others} | {r['public_port'] for c in others for r in c['rules']}
    ports |= {r['public_port'] for r in rules}
    if listen_port is not None: ports.add(listen_port)
    return ports


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


def prompt_for_rules(target_ip, others, listen_port):
    print("\n--- Port Forwarding Rules ---")
    rules = []
    while confirm("Add a forwarding rule?", default=True):
        print("  - New Rule -")
        comment = ask("  Description (e.g. Web Server)", "Forwarded Rule", validate_comment)
        protocol = ask("  Protocol (tcp/udp)", "tcp", validate_protocol)

        def check_public(value):
            port = validate_port(value)
            check_public_port_free(others, protocol, port, rules, listen_port)
            return port
        pub_port = ask("  Public Port on Server", get_random_port(used_ports(others, rules, listen_port)), check_public)
        if pub_port in SENSITIVE_PORTS and not confirm(
                f"  Port {pub_port} ({SENSITIVE_PORTS[pub_port]}) is used by the VPS itself; forwarding it will hijack that service. Continue?"):
            continue
        rules.append({
            "comment": comment,
            "protocol": protocol,
            "public_port": pub_port,
            "target_ip": target_ip,
            "target_port": ask("  Target Port on Client", pub_port, validate_port)
        })
        print("  > Rule added.")
    return rules


def add_new_client(session):
    config = session.config
    clients = config['clients']
    print("\n--- Add New Client ---")
    client_name = ask("Enter a unique name for the client (e.g., 'minecraft-server')", validate=name_validator(clients))

    managed_interfaces = {c['interface_name'] for c in clients}
    interface_name = ask("Enter the interface name for this client", get_next_interface_name(config),
                         interface_validator(clients))

    check_subnet, host_networks = subnet_validator(clients, managed_interfaces)
    taken = [ipaddress.ip_interface(c['server_address']).network for c in clients] + host_networks
    server_address = ask("Enter VPN subnet for this client (CIDR)", get_random_subnet(taken), check_subnet)
    client_ip = client_ip_for(server_address)

    srv_priv, srv_pub = generate_keypair()
    cli_priv, cli_pub = generate_keypair()
    print(f"\n> Generated Server Public Key: {srv_pub}\n> Generated Client Public Key: {cli_pub}")

    listen_port = ask("WireGuard Listen Port for this client", get_random_port(used_ports(clients)),
                      listen_port_validator(clients))
    client_data = {
        "name": client_name, "interface_name": interface_name,
        "listen_port": listen_port,
        "server_address": server_address, "server_private_key": srv_priv,
        "client_public_key": cli_pub, "client_allowed_ips": f"{client_ip}/32",
        "rules": prompt_for_rules(client_ip, clients, listen_port),
        "full_tunnel": confirm("Route all client internet traffic through VPN (full tunnel)?")
    }

    if apply_client_config(client_data, config['public_interface']):
        clients.append(client_data)
        session.save()
        print(f"\n[+] Client '{client_name}' added to config.")
        generate_and_print_client_config(client_data, srv_pub, cli_priv)


def edit_existing_client(session):
    config = session.config
    print("\n--- Edit an Existing Client ---")
    if not list_clients(config, show_details=False): return

    index = select_client(config, "edit")
    if index is None: return
    original = config['clients'][index]
    others = [c for i, c in enumerate(config['clients']) if i != index]
    managed_interfaces = {c['interface_name'] for c in config['clients']}
    # Edit a copy; the stored client only changes once the new config is live.
    draft = copy.deepcopy(original)

    while True:
        print(f"\n--- Editing '{draft['name']}'{' (unsaved changes)' if draft != original else ''} ---")
        print("1. Edit Name")
        print("2. Edit Interface Name")
        print("3. Edit VPN Subnet")
        print("4. Edit Listen Port")
        print("5. Edit Full Tunnel Status")
        print("6. Edit Rules")
        print("7. Apply changes and go back")
        print("8. Discard changes and go back")
        edit_choice = get_input("Choose an option", "7")

        if edit_choice == '1':
            draft['name'] = ask("Unique name for the client", draft['name'], name_validator(others))
        elif edit_choice == '2':
            draft['interface_name'] = ask("Interface name", draft['interface_name'],
                                          interface_validator(others, current=original['interface_name']))
        elif edit_choice == '3':
            check_subnet, _ = subnet_validator(others, managed_interfaces)
            draft['server_address'] = ask("VPN subnet (CIDR)", draft['server_address'], check_subnet)
            new_client_ip = client_ip_for(draft['server_address'])
            draft['client_allowed_ips'] = f"{new_client_ip}/32"
            for rule in draft['rules']: rule['target_ip'] = new_client_ip
        elif edit_choice == '4':
            draft['listen_port'] = ask("WireGuard Listen Port", draft['listen_port'],
                                       listen_port_validator(others, draft['rules']))
        elif edit_choice == '5':
            draft['full_tunnel'] = confirm("Full tunnel?", default=bool(draft.get('full_tunnel')))
        elif edit_choice == '6':
            print("\nNote: You will need to re-enter all port forwarding rules.")
            draft['rules'] = prompt_for_rules(client_ip_for(draft['server_address']), others, draft['listen_port'])
        elif edit_choice == '7':
            if draft == original:
                print("No changes to apply.")
                break
            if apply_client_config(draft, config['public_interface'], previous=original):
                config['clients'][index] = draft
                session.save()
                print(f"\n[+] Client '{draft['name']}' updated successfully.")
                break
            print(f"\n[-] Failed to apply changes for client '{draft['name']}'; the previous configuration is still in place.", file=sys.stderr)
            print("    Adjust the settings and try again, or discard the changes.", file=sys.stderr)
        elif edit_choice == '8':
            print("Changes discarded.")
            break
        else:
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
            print(f"  - {tunnel_type}, Listen Port: {client['listen_port']}, VPN Subnet: {client['server_address']}")
            print(f"  - Rules: {len(client['rules'])}")
            for j, rule in enumerate(client['rules']):
                print(f"    {j+1}. {rule['protocol']}:{rule['public_port']} -> {rule['target_ip']}:{rule['target_port']}")
    return True


def remove_client(session):
    config = session.config
    print("\n--- Remove a Client ---")
    if not list_clients(config, show_details=False): return

    index = select_client(config, "remove")
    if index is None: return
    client_to_remove = config['clients'][index]
    if confirm(f"Are you sure you want to remove '{client_to_remove['name']}'?"):
        if remove_client_config(client_to_remove):
            config['clients'].pop(index)
            session.save()
            print(f"\n[+] Client '{client_to_remove['name']}' removed from config.")
    else: print("Cancelled.")
