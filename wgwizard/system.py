import ipaddress
import os
import shutil
import subprocess
import sys

from .errors import WizardError
from .fsutil import write_private_file
from .rendering import generate_wg_config_for_client


def is_root():
    return sys.platform != "win32" and os.geteuid() == 0


def check_root():
    """Raise unless the script can modify system services and configs."""
    if sys.platform == "win32":
        raise WizardError("This script needs to modify system services and must be run on Linux.")
    if os.geteuid() != 0:
        raise WizardError("This script must be run as root (using 'sudo') to manage services and configs.")


FORWARDING_CONF = '/etc/sysctl.d/99-wg-wizard-forwarding.conf'


def enable_ip_forwarding():
    """Ensures IPv4 forwarding is on now and persisted via a sysctl.d drop-in."""
    try:
        result = subprocess.run(['sysctl', '-n', 'net.ipv4.ip_forward'], text=True, capture_output=True)
        if result.stdout.strip() == "1" and os.path.exists(FORWARDING_CONF):
            return # Already enabled and persisted
        write_private_file(FORWARDING_CONF, 'net.ipv4.ip_forward = 1\n', mode=0o644)
        subprocess.run(['sysctl', '-p', FORWARDING_CONF], check=True, capture_output=True)
        print("[+] IP forwarding has been enabled for the system.")
    except (OSError, subprocess.CalledProcessError) as e:
        raise WizardError(f"Error enabling IP forwarding: {e}") from e


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

    try:
        config_content = generate_wg_config_for_client(client_data, public_interface)
    except ValueError as e:
        print(f"  Error: refusing to apply invalid configuration: {e}", file=sys.stderr)
        return False
    config_path = f"{wg_config_dir}/{iface_name}.conf"

    try:
        write_private_file(config_path, config_content)
        print(f"  > Configuration saved to {config_path}")
    except OSError as e:
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
    """Generates a WireGuard private and public key pair.

    The private key is handed to `wg pubkey` on stdin so it never appears in
    any process's argument list.
    """
    if not shutil.which("wg"):
        raise WizardError("'wg' command not found. Please install wireguard-tools.")
    try:
        privkey = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
        pubkey = subprocess.run(["wg", "pubkey"], input=privkey + "\n", check=True, capture_output=True, text=True).stdout.strip()
        return privkey, pubkey
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise WizardError(f"Error generating WireGuard keypair: {e}") from e


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
        ip = subprocess.check_output(["curl", "-4", "-s", "-f", "--max-time", "10", "https://ifconfig.me"], text=True).strip()
        ipaddress.ip_address(ip) # Basic validation
        print(f"  > Detected public IPv4: {ip}")
        return ip
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError) as e:
        print(f"  > Warning: Could not determine public IP address: {e}", file=sys.stderr)
        return "<YOUR_SERVER_PUBLIC_IP>"
