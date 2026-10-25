# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A standard-library-only Python 3 CLI that manages a multi-tenant WireGuard reverse-proxy hub on a Debian/Ubuntu VPS. Each client gets its own WireGuard interface (`wg0`, `wg1`, …), its own `10.x.x.1/24` subnet, iptables DNAT port-forwarding rules, and per-client isolation chains. `wizard.py` is only the entry point; the code is in the `wgwizard/` package. See `README.md` for the architecture diagram and user-facing docs.

```bash
sudo python3 wizard.py            # state in config.json next to wizard.py
sudo python3 wizard.py -f path.json
python -m unittest discover -s tests -t .          # all tests (run on any OS)
python -m unittest tests.test_service.ApplyClientConfig.test_failed_stop_changes_nothing   # one test
```

The tool itself needs Linux, root, and `wg`, `wg-quick`, `systemctl`, `iptables`, `ip` and `curl`. The tests mock all of that, so they run on the Windows dev machine. Non-root and Windows runs start in read-only mode (listing works, mutating menu actions are refused). There is no linter.

**Never put backslash escapes in Bash heredocs** (`\n` etc.) when generating files from shell: the tool layer rewrites them and silently produces broken string literals. Use the Write/Edit tools for file content. `tests/test_imports.py` exists to catch that kind of breakage.

## Architecture

Dependency direction is roughly `cli → actions → service/host/store → rendering → validation`.

- **`validation.py`** (pure): strict validators plus uniqueness checks (`check_*_free`, `find_conflicts`). `validate_client` is the gate for everything that ends up in a wg-quick `PostUp`/`PostDown` hook, because those are run by a root shell. It is applied on typed input, on config load, and again inside the renderer. Add a validator here for any new field that reaches a hook or a file path.
- **`rendering.py`** (pure): `generate_wg_config_for_client` builds the server-side conf; `render_client_config` builds the client's. Firewall rules are collected in `_Firewall` as `(up, down)` pairs so `PostDown` is generated as the reverse of `PostUp` and cannot drift. Each client gets chains `WGW-F-<iface>` (FORWARD) and `WGW-I-<iface>` (INPUT) ending in `DROP`, hooked at the top of the built-in chains; isolation must not depend on the global FORWARD policy.
- **`service.py`**: conf-file + systemd lifecycle. `apply_client_config(client, public_if, previous=None)` **stops the old interface before writing the new conf**, because `wg-quick down` reads `PostDown` from the file on disk at stop time. It rolls back to the previous conf on any failure (including Ctrl-C). `previous` is passed on edits so interface renames clean up the old conf/service.
- **`host.py`**: facts about the machine (root check, forwarding sysctl, keypair via `wg`, public IP, local networks, live interface status).
- **`store.py`**: `Session` holds the config and an `flock` on `<config>.lock`; `Session.save()` is called after every successful change and writes atomically (via `fsutil.write_private_file`, always 0600) keeping `<config>.bak`. Any code that mutates `session.config` must call `save()` after the system change succeeds.
- **`actions.py`**: the interactive menu flows. Editing works on a `deepcopy` draft and only replaces the stored client after `apply_client_config` succeeds. Prompts go through `prompts.ask(prompt, default, validator)`, which re-prompts on `ValueError`.
- **`errors.py`**: `WizardError` is the user-facing failure type; `cli.run_menu` prints it and returns to the menu. Library code raises it instead of calling `sys.exit`.

## Data model and invariants

`config.json` is `public_interface` plus `clients[]` with `name`, `interface_name` (`^wg\d+$`), `listen_port`, `server_address` (CIDR; server `.1`, client = server IP + 1), `server_private_key`, `client_public_key`, `client_allowed_ips`, `rules[]` (`comment`, `protocol`, `public_port`, `target_ip`, `target_port`), `full_tunnel`. `client_allowed_ips` and every `rule.target_ip` are derived from `server_address`; `validate_client` rejects stale values, so update them together (the subnet-edit flow does). The client private key is never stored; if the wizard generated it, it is shown once. Uniqueness is enforced per protocol for public ports, and UDP forwards may not collide with any WireGuard listen port.

Only conf files starting with `MANAGED_HEADER` (`# Auto-generated for client:`) are treated as ours; interface names whose conf or network device already exists are refused so a missing `config.json` cannot cause an overwrite.

## Not verified on a real host

The generated iptables rules and the stop/write/start sequence were tested only through string assertions and mocked `systemctl`, never against a live `iptables`/`wg-quick`. Check them on a VPS (`iptables -S`, `wg show`, a real DNAT'd connection and a client-to-client probe) before relying on any change to `rendering.py` or `service.py`.
