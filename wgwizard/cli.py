import argparse
import os
import sys

from .actions import add_new_client, edit_existing_client, list_clients, remove_client
from .prompts import get_input
from .store import load_config, save_config
from .system import enable_ip_forwarding, reapply_all_configs


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
