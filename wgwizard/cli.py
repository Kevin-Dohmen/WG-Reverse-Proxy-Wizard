import argparse
import os
import sys

from .actions import add_new_client, edit_existing_client, list_clients, remove_client
from .errors import ConfigError, WizardError
from .prompts import get_input
from .store import load_config, save_config
from .host import check_root, enable_ip_forwarding, is_root
from .service import reapply_all_configs

# Menu actions that change the system and therefore need root.
MUTATING = {'2', '3', '4', '5'}


def main():
    parser = argparse.ArgumentParser(description="All-in-One WireGuard Configuration Wizard")
    parser.add_argument("-f", "--file", default="config.json", help="Path to the JSON configuration file")
    args = parser.parse_args()

    try:
        config = load_config(args.file)
    except ConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("--- WireGuard Multi-Client Wizard ---")

    # Proactively enable IP forwarding if running as root
    if is_root():
        try:
            enable_ip_forwarding()
        except WizardError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Warning: not running as root. Add/edit/remove/re-apply will be refused (read-only mode).", file=sys.stderr)

    while True:
        print("\nMenu:")
        print("1. List existing clients")
        print("2. Add a new client")
        print("3. Edit a client")
        print("4. Remove a client")
        print("5. Re-apply all configurations")
        print("6. Save and Exit")
        choice = get_input("Choose an option", "1")

        try:
            if choice in MUTATING: check_root()
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
        except WizardError as e:
            print(f"Error: {e}", file=sys.stderr)
