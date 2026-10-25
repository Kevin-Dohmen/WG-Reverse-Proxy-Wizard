"""Facts about, and one-off changes to, the host the wizard runs on."""
import ipaddress
import os
import shutil
import subprocess
import sys

from .errors import WizardError
from .fsutil import write_private_file

FORWARDING_CONF = '/etc/sysctl.d/99-wg-wizard-forwarding.conf'


def is_root():
    return sys.platform != "win32" and os.geteuid() == 0


def check_root():
    """Raise unless the script can modify system services and configs."""
    if sys.platform == "win32":
        raise WizardError("This script needs to modify system services and must be run on Linux.")
    if os.geteuid() != 0:
        raise WizardError("This script must be run as root (using 'sudo') to manage services and configs.")


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
    except (subprocess.CalledProcessError, FileNotFoundError): pass
    return "eth0"


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
