import ipaddress
import os
import shutil
import subprocess
import sys

from .rendering import generate_wg_config_for_client


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
