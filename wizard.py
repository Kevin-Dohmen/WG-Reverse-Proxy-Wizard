#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import shutil
import os
import ipaddress
import random
import string

# --- System & Service Management Functions (from init_iface.py) ---

def check_root():
    """Exit if the script is not run as root on a non-Windows OS."""
    if sys.platform == "win32":
        print("Error: This script needs to modify system services and must be run on Linux.", file=sys.stderr)
        sys.exit(1)
    if os.geteuid() != 0:
        print("Error: This script must be run as root (using 'sudo') to manage services and configs.", file=sys.stderr)
        sys.exit(1)

def enable_ip_forwarding_debian():
    """Ensures IP forwarding is enabled using the sysctl.d directory."""
    conf_path = '/etc/sysctl.d/99-gemini-forwarding.conf'
    try:
        result = subprocess.run(['sysctl', 'net.ipv4.ip_forward'], text=True, capture_output=True)
        if "net.ipv4.ip_forward = 1" in result.stdout and os.path.exists(conf_path):
            return # Already enabled and configured
        with open(conf_path, 'w') as f: f.write('net.ipv4.ip_forward = 1\n')
        subprocess.run(['sysctl', '-p', conf_path], check=True, capture_output=True)
        print("[+] IP forwarding has been enabled for the system.")
    except Exception as e:
        print(f"Error enabling IP forwarding (Debian method): {e}", file=sys.stderr)
        sys.exit(1)

def enable_ip_forwarding():
    """Ensures IP forwarding is enabled, trying the legacy method first."""
    if not os.path.exists('/etc/sysctl.conf'):
        enable_ip_forwarding_debian()
        return
    try:
        result = subprocess.run(['sysctl', 'net.ipv4.ip_forward'], text=True, capture_output=True)
        if "net.ipv4.ip_forward = 1" in result.stdout: return
        with open('/etc/sysctl.conf', 'r+') as f:
            lines, found = f.readlines(), False
            for line in lines:
                if line.strip().startswith('net.ipv4.ip_forward'): found = True
            if not found: lines.append('\nnet.ipv4.ip_forward = 1\n')
            f.seek(0), f.truncate(), f.writelines(lines)
        subprocess.run(['sysctl', '-p'], check=True, capture_output=True)
        print("[+] IP forwarding has been enabled for the system.")
    except Exception as e:
        print(f"Error enabling IP forwarding: {e}", file=sys.stderr)
        sys.exit(1)

def manage_service(action, interface_name, quiet=False):
    """Manages a wg-quick systemd service."""
    service_name = f"wg-quick@{interface_name}"
    try:
        # Use run instead of check_output to handle errors gracefully
        result = subprocess.run(
            ["systemctl", action, service_name],
            check=True, capture_output=True, text=True
        )
        if not quiet: print(f"  > Service '{service_name}' {action}ed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        # Don't raise an error if the service didn't exist, which is expected on removal.
        stderr = e.stderr.strip() if e.stderr else ""
        if "does not exist" in stderr or "No such file or directory" in stderr:
            if not quiet: print(f"  > Service '{service_name}' not found, no action taken.")
            return True # Not an error in this context
        print(f"  Error: Failed to {action} service '{service_name}'.", file=sys.stderr)
        print(f"    Stderr: {stderr}", file=sys.stderr)
        return False

def generate_wg_config_for_client(client_data, public_interface):
    """Generates the server-side WireGuard config content for a client."""
    interface_name = client_data['interface_name']
    server_address_with_subnet = client_data['server_address']
    server_subnet = str(ipaddress.ip_interface(server_address_with_subnet).network)

    content = [
        f"# Auto-generated for client: {client_data['name']}",
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

def apply_client_config(client_data, public_interface):
    """Writes the server config file and restarts the service."""
    iface_name = client_data['interface_name']
    print(f"[*] Applying configuration for '{client_data['name']}' ({iface_name})...")
    check_root()
    
    # Ensure /etc/wireguard exists
    wg_config_dir = "/etc/wireguard"
    if not os.path.isdir(wg_config_dir):
        os.makedirs(wg_config_dir)
        print(f"  > Created directory: {wg_config_dir}")

    config_content = generate_wg_config_for_client(client_data, public_interface)
    config_path = f"{wg_config_dir}/{iface_name}.conf"

    try:
        with open(config_path, 'w') as f: f.write(config_content)
        os.chmod(config_path, 0o600)
        print(f"  > Configuration saved to {config_path}")
    except IOError as e:
        print(f"  Error writing config file: {e}", file=sys.stderr)
        return False
    
    # Reload systemd, then enable and restart the specific service
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    manage_service("enable", iface_name)
    manage_service("restart", iface_name)
    print(f"[+] Client '{client_data['name']}' is now active.")
    return True

def remove_client_config(client_data):
    """Stops the service and removes the server config file."""
    iface_name = client_data['interface_name']
    print(f"[*] Removing configuration for '{client_data['name']}' ({iface_name})...")
    check_root()
    
    manage_service("stop", iface_name)
    manage_service("disable", iface_name)

    config_path = f"/etc/wireguard/{iface_name}.conf"
    if os.path.exists(config_path):
        try:
            os.remove(config_path)
            print(f"  > Removed server config: {config_path}")
        except OSError as e:
            print(f"  Error removing file: {e}", file=sys.stderr)
            return False
    print(f"[+] Client '{client_data['name']}' has been deactivated.")
    return True

def reapply_all_configs(config):
    """Iterates through all clients and re-applies their configuration."""
    print("\n--- Re-applying All Server Configurations ---")
    if not config['clients']:
        print("No clients to re-apply.")
        return
    for client in config['clients']:
        apply_client_config(client, config['public_interface'])
    print("\n[+] All configurations have been re-applied.")

# --- Wizard Core Functions ---

def generate_keypair():
    """Generates a WireGuard private and public key pair safely."""
    if not shutil.which("wg"):
        print("Error: 'wg' command not found. Please install wireguard-tools.", file=sys.stderr)
        sys.exit(1)
    try:
        privkey = subprocess.check_output(["wg", "genkey"], text=True).strip()
        p1 = subprocess.Popen(["echo", privkey], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["wg", "pubkey"], stdin=p1.stdout, stdout=subprocess.PIPE, text=True)
        p1.stdout.close()
        pubkey = p2.communicate()[0].strip()
        if p2.returncode != 0: raise subprocess.CalledProcessError(p2.returncode, p2.args)
        return privkey, pubkey
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error generating WireGuard keypair: {e}", file=sys.stderr)
        sys.exit(1)

def get_input(prompt, default=None, required=True):
    prompt_text = f"{prompt}"
    if default is not None: prompt_text += f" [{default}]"
    prompt_text += ": "
    while True:
        user_input = input(prompt_text).strip()
        if user_input: return user_input
        if default is not None: return str(default)
        if required: print("Error: This field is required.", file=sys.stderr)
        else: return ""

def load_config(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f: return json.load(f)
    return {"public_interface": get_default_public_interface(), "clients": []}

def save_config(filepath, data):
    with open(filepath, 'w') as f: json.dump(data, f, indent=4)

def get_default_public_interface():
    try:
        result = subprocess.check_output(["ip", "route", "get", "1.1.1.1"], text=True)
        if "dev" in (parts := result.split()): return parts[parts.index("dev") + 1]
    except (subprocess.CalledProcessError, FileNotFoundError): return "eth0"

def get_public_ip():
    """Fetches the public IP address of the server."""
    if not shutil.which("curl"):
        print("  > Warning: 'curl' command not found. Unable to automatically determine public IP.", file=sys.stderr)
        return "<YOUR_SERVER_PUBLIC_IP>"
    try:
        ip = subprocess.check_output(["curl", "-4", "-s", "ifconfig.me"], text=True).strip()
        ipaddress.ip_address(ip) # Basic validation
        print(f"  > Detected public IPv4: {ip}")
        return ip
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError) as e:
        print(f"  > Warning: Could not determine public IP address: {e}", file=sys.stderr)
        return "<YOUR_SERVER_PUBLIC_IP>"

def get_random_port(used_ports):
    while True:
        port = random.randint(49152, 65535)
        if port not in used_ports: return port

def get_random_subnet(used_subnets):
    while True:
        subnet = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.1/24"
        if subnet not in used_subnets: return subnet

def get_next_interface_name(config):
    used_indices = {int(c['interface_name'][2:]) for c in config.get('clients', []) if c.get('interface_name', '').startswith('wg') and c['interface_name'][2:].isdigit()}
    next_index = 0
    while next_index in used_indices: next_index += 1
    return f"wg{next_index}"

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

def main():
    parser = argparse.ArgumentParser(description="All-in-One WireGuard Configuration Wizard")
    parser.add_argument("-f", "--file", default="config.json", help="Path to the JSON configuration file")
    args = parser.parse_args()

    # Check for root at the start if any system modification might be needed
    if len(sys.argv) > 1 and sys.argv[1] not in ['-h', '--help']:
        if os.geteuid() != 0:
            print("Warning: Script not run as root. Some actions (add/edit/remove) will fail.", file=sys.stderr)
            print("         Running in read-only mode.\n", file=sys.stderr)

    config = load_config(args.file)
    
    print("--- WireGuard Multi-Client Wizard ---")
    
    # Proactively enable IP forwarding if running as root
    if os.geteuid() == 0:
        enable_ip_forwarding()

    while True:
        print("\nMenu:")
        print("1. List existing clients")
        print("2. Add a new client")
        print("3. Edit a client")
        print("4. Remove a client")
        print("5. Re-apply all configurations")
        print("6. Save and Exit")
        choice = get_input("Choose an option", "1")

        if choice == '1': list_clients(config)
        elif choice == '2': add_new_client(config)
        elif choice == '3': edit_existing_client(config)
        elif choice == '4': remove_client(config)
        elif choice == '5': reapply_all_configs(config)
        elif choice == '6':
            save_config(args.file, config)
            print(f"\nConfiguration saved to {os.path.abspath(args.file)}")
            print("Run 'sudo wg show' on the server to see live status.")
            break
        else: print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()