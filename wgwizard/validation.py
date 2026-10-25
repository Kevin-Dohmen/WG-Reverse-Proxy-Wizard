"""Pure input validators.

Everything that ends up in a wg-quick PostUp/PostDown hook is executed by a
root shell, so values are checked against strict patterns both when typed in
and when loaded from config.json.
"""
import ipaddress
import re

IFACE_RE = re.compile(r"^wg[0-9]{1,4}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
NIC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
PROTOCOLS = ("tcp", "udp")
# Public ports that would shadow a service on the VPS itself.
SENSITIVE_PORTS = {22: "SSH"}


def is_safe_text(value, max_len=128):
    """Printable, single-line text (safe to embed in a '#' comment)."""
    return isinstance(value, str) and 0 < len(value) <= max_len and value.isprintable()


def validate_name(value):
    if not NAME_RE.match(value):
        raise ValueError("name must be 1-64 characters: letters, digits, space, '.', '_' or '-' (starting with a letter or digit)")
    return value


def validate_comment(value):
    value = value.strip()
    if not is_safe_text(value, 80):
        raise ValueError("description must be 1-80 printable characters")
    return value


def validate_interface(value):
    if not IFACE_RE.match(value):
        raise ValueError("interface name must look like 'wg0', 'wg1', ...")
    return value


def validate_public_interface(value):
    if not NIC_RE.match(value):
        raise ValueError(f"'{value}' is not a valid network interface name")
    return value


def validate_protocol(value):
    value = value.strip().lower()
    if value not in PROTOCOLS:
        raise ValueError("protocol must be 'tcp' or 'udp'")
    return value


def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"'{value}' is not a number") from None
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return port


def validate_server_address(value):
    """Server-side tunnel address in CIDR form; the client gets the next IP."""
    try:
        iface = ipaddress.ip_interface(value)
    except ValueError as e:
        raise ValueError(f"invalid CIDR address: {e}") from None
    if iface.version != 4 or "/" not in str(value):
        raise ValueError("enter an IPv4 address with a prefix length, e.g. 10.20.30.1/24")
    if not 16 <= iface.network.prefixlen <= 30:
        raise ValueError("prefix length must be between /16 and /30")
    client = iface.ip + 1
    if client not in iface.network or client == iface.network.broadcast_address:
        raise ValueError("no usable client address after the server address in this subnet")
    if iface.ip == iface.network.network_address:
        raise ValueError("server address must not be the network address")
    return str(iface)


def client_ip_for(server_address):
    """The client's tunnel IP: always the address right after the server's."""
    return str(ipaddress.ip_interface(server_address).ip + 1)


def validate_wg_key(value):
    value = value.strip()
    if not WG_KEY_RE.match(value):
        raise ValueError("not a valid WireGuard key (expected 44 base64 characters)")
    return value


def validate_client(client):
    """Validate a full client record; raises ValueError describing the first problem."""
    try:
        name = client['name']
        if not is_safe_text(name, 128):
            raise ValueError("name must be printable single-line text")
        validate_interface(client['interface_name'])
        validate_port(client['listen_port'])
        validate_server_address(client['server_address'])
        validate_wg_key(client['server_private_key'])
        validate_wg_key(client['client_public_key'])
        expected_ip = client_ip_for(client['server_address'])
        if client['client_allowed_ips'] != f"{expected_ip}/32":
            raise ValueError(f"client_allowed_ips must be {expected_ip}/32")
        for rule in client['rules']:
            if not is_safe_text(rule.get('comment', 'Rule'), 128):
                raise ValueError("rule description must be printable single-line text")
            validate_protocol(rule['protocol'])
            validate_port(rule['public_port'])
            validate_port(rule['target_port'])
            if rule['target_ip'] != expected_ip:
                raise ValueError(f"rule target_ip must be {expected_ip}")
    except KeyError as e:
        raise ValueError(f"missing field {e}") from None
    except TypeError as e:
        raise ValueError(f"malformed value ({e})") from None
    return client


# --- Uniqueness checks against the other clients ------------------------------
# `clients` is always the list of *other* clients (the one being added or
# edited is excluded by the caller).

def check_name_free(clients, name):
    if any(c['name'] == name for c in clients):
        raise ValueError(f"a client named '{name}' already exists")


def check_interface_free(clients, interface_name):
    if any(c['interface_name'] == interface_name for c in clients):
        raise ValueError(f"interface {interface_name} is already used by another client")


def _udp_ports_in_use(clients, rules=()):
    ports = {c['listen_port'] for c in clients}
    ports |= {r['public_port'] for c in clients for r in c['rules'] if r['protocol'] == 'udp'}
    ports |= {r['public_port'] for r in rules if r['protocol'] == 'udp'}
    return ports


def check_listen_port_free(clients, port, own_rules=()):
    """A WireGuard listen port is UDP, so it also clashes with UDP forwarding rules."""
    if port in _udp_ports_in_use(clients, own_rules):
        raise ValueError(f"UDP port {port} is already used by another listen port or forwarding rule")


def check_public_port_free(clients, protocol, port, own_rules=(), own_listen_port=None):
    taken = {(r['protocol'], r['public_port']) for c in clients for r in c['rules']}
    taken |= {(r['protocol'], r['public_port']) for r in own_rules}
    taken |= {('udp', c['listen_port']) for c in clients}
    if own_listen_port is not None: taken.add(('udp', own_listen_port))
    if (protocol, port) in taken:
        raise ValueError(f"{protocol.upper()} port {port} is already forwarded or used as a WireGuard listen port")


def check_subnet_free(clients, server_address, host_networks=()):
    network = ipaddress.ip_interface(server_address).network
    for c in clients:
        if network.overlaps(ipaddress.ip_interface(c['server_address']).network):
            raise ValueError(f"overlaps the subnet of client '{c['name']}' ({c['server_address']})")
    for other in host_networks:
        if network.overlaps(other):
            raise ValueError(f"overlaps a network already configured on this host ({other})")


def find_conflicts(config):
    """Human-readable list of clashes between clients already in a config."""
    problems = []
    clients = config['clients']
    for i, client in enumerate(clients):
        rest = clients[:i]  # report each pair once
        label = f"client '{client['name']}'"
        for check, args in (
            (check_name_free, (client['name'],)),
            (check_interface_free, (client['interface_name'],)),
            (check_subnet_free, (client['server_address'],)),
            (check_listen_port_free, (client['listen_port'], client['rules'])),
        ):
            try: check(rest, *args)
            except ValueError as e: problems.append(f"{label}: {e}")
        seen = []
        for rule in client['rules']:
            try: check_public_port_free(rest, rule['protocol'], rule['public_port'], seen, client['listen_port'])
            except ValueError as e: problems.append(f"{label}: {e}")
            seen.append(rule)
    return problems
