"""Lifecycle of the per-client wg-quick conf files and systemd services."""
import os
import subprocess
import sys

from .errors import WizardError
from .fsutil import write_private_file
from .host import check_root, interface_exists
from .rendering import MANAGED_HEADER, generate_wg_config_for_client

WG_DIR = "/etc/wireguard"
PAST_TENSE = {"start": "started", "stop": "stopped", "enable": "enabled", "disable": "disabled"}


def conf_path(interface_name):
    return os.path.join(WG_DIR, f"{interface_name}.conf")


def read_conf(interface_name):
    """Current text of the interface's conf file, or None if it doesn't exist."""
    try:
        with open(conf_path(interface_name), 'r') as f: return f.read()
    except FileNotFoundError:
        return None


def manage_service(action, interface_name, quiet=False):
    """Run a systemctl action on a wg-quick service; returns True on success."""
    service_name = f"wg-quick@{interface_name}"
    try:
        subprocess.run(["systemctl", action, service_name], check=True, capture_output=True, text=True)
        if not quiet: print(f"  > Service '{service_name}' {PAST_TENSE.get(action, action + 'ed')} successfully.")
        return True
    except FileNotFoundError as e:
        raise WizardError("'systemctl' not found; a systemd-based Linux host is required.") from e
    except subprocess.CalledProcessError as e:
        # Don't raise an error if the service didn't exist, which is expected on removal.
        stderr = e.stderr.strip() if e.stderr else ""
        if "does not exist" in stderr or "No such file or directory" in stderr:
            if not quiet: print(f"  > Service '{service_name}' not found, no action taken.")
            return True # Not an error in this context
        print(f"  Error: Failed to {action} service '{service_name}'.", file=sys.stderr)
        print(f"    Stderr: {stderr}", file=sys.stderr)
        print(f"    Details: journalctl -xeu {service_name}", file=sys.stderr)
        return False


def _remove_conf(interface_name):
    try:
        os.remove(conf_path(interface_name))
    except FileNotFoundError:
        pass


def _rollback(interface_name, previous_interface, previous_text):
    """Undo a failed apply: drop the new conf and bring the previous one back up."""
    print("  > Rolling back to the previous configuration...", file=sys.stderr)
    manage_service("stop", interface_name, quiet=True)
    if interface_name != previous_interface or previous_text is None:
        manage_service("disable", interface_name, quiet=True)
        _remove_conf(interface_name)
    if previous_text is None:
        return
    try:
        write_private_file(conf_path(previous_interface), previous_text)
    except OSError as e:
        print(f"  Error restoring {conf_path(previous_interface)}: {e}", file=sys.stderr)
        return
    if manage_service("enable", previous_interface, quiet=True) and manage_service("start", previous_interface, quiet=True):
        print("  > Previous configuration restored.", file=sys.stderr)
    else:
        print("  > Could not restart the previous configuration; check the service manually.", file=sys.stderr)


def apply_client_config(client_data, public_interface, previous=None):
    """Write the client's server-side config and (re)start its interface.

    `previous` is the version being replaced when editing, so a renamed
    interface is cleaned up. The old interface is always stopped *before* any
    file is touched: wg-quick runs the PostDown lines found in the conf at stop
    time, so stopping after the rewrite would try to delete rules that were
    never added and leave the real ones behind. If anything fails the previous
    conf is restored and restarted.
    """
    iface_name = client_data['interface_name']
    previous_iface = previous['interface_name'] if previous else iface_name
    print(f"[*] Applying configuration for '{client_data['name']}' ({iface_name})...")
    check_root()

    try:
        config_content = generate_wg_config_for_client(client_data, public_interface)
    except ValueError as e:
        print(f"  Error: refusing to apply invalid configuration: {e}", file=sys.stderr)
        return False

    previous_text = read_conf(previous_iface)
    if previous_iface != iface_name and read_conf(iface_name) is not None:
        print(f"  Error: {conf_path(iface_name)} already exists and is not managed by this client.", file=sys.stderr)
        return False

    if not manage_service("stop", previous_iface):
        print("  Aborting: the running interface could not be stopped, nothing was changed.", file=sys.stderr)
        return False

    try:
        try:
            os.makedirs(WG_DIR, mode=0o700, exist_ok=True)
            write_private_file(conf_path(iface_name), config_content)
            print(f"  > Configuration saved to {conf_path(iface_name)}")
            if previous_iface != iface_name:
                manage_service("disable", previous_iface, quiet=True)
                _remove_conf(previous_iface)
        except OSError as e:
            print(f"  Error writing config file: {e}", file=sys.stderr)
            _rollback(iface_name, previous_iface, previous_text)
            return False

        if manage_service("enable", iface_name) and manage_service("start", iface_name):
            print(f"[+] Client '{client_data['name']}' is now active.")
            return True

        print(f"[-] Client '{client_data['name']}' failed to start.", file=sys.stderr)
        _rollback(iface_name, previous_iface, previous_text)
        return False
    except KeyboardInterrupt:
        # Never leave the interface half-configured and stopped because of a stray Ctrl-C.
        _rollback(iface_name, previous_iface, previous_text)
        raise


def remove_client_config(client_data):
    """Stops the service and removes the server config file."""
    iface_name = client_data['interface_name']
    print(f"[*] Removing configuration for '{client_data['name']}' ({iface_name})...")
    check_root()

    if not manage_service("stop", iface_name):
        print("  Aborting: the interface could not be stopped; its firewall rules may still be active.", file=sys.stderr)
        return False
    manage_service("disable", iface_name)

    try:
        if os.path.exists(conf_path(iface_name)):
            os.remove(conf_path(iface_name))
            print(f"  > Removed server config: {conf_path(iface_name)}")
    except OSError as e:
        print(f"  Error removing file: {e}", file=sys.stderr)
        return False
    print(f"[+] Client '{client_data['name']}' has been deactivated.")
    return True


def reapply_all_configs(config):
    """Re-applies every client's configuration; returns the names of any that failed."""
    print("\n--- Re-applying All Server Configurations ---")
    if not config['clients']:
        print("No clients to re-apply.")
        return []
    failed = [c['name'] for c in config['clients'] if not apply_client_config(c, config['public_interface'])]
    if failed:
        print(f"\n[-] Failed to re-apply: {', '.join(failed)}", file=sys.stderr)
    else:
        print("\n[+] All configurations have been re-applied.")
    return failed


def ensure_interface_unused(interface_name):
    """Raise ValueError if something else already owns this interface name or conf file."""
    if interface_exists(interface_name):
        raise ValueError(f"a network interface named {interface_name} already exists on this host")
    if os.path.exists(conf_path(interface_name)):
        raise ValueError(f"{conf_path(interface_name)} already exists and is not managed by this tool's config")


def unmanaged_confs(known_interfaces):
    """Interfaces whose wizard-generated conf exists on disk but is missing from the config."""
    try:
        names = sorted(f[:-5] for f in os.listdir(WG_DIR) if f.endswith(".conf"))
    except OSError:
        return []
    found = []
    for name in names:
        if name in known_interfaces: continue
        text = read_conf(name)
        if text and text.startswith(MANAGED_HEADER): found.append(name)
    return found
