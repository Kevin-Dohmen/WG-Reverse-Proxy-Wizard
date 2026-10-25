"""Pure text generation: the server-side wg-quick config for a client."""
import ipaddress

from .validation import client_ip_for, validate_client, validate_public_interface

# First line of every conf we write; lets us tell our files from foreign ones.
MANAGED_HEADER = "# Auto-generated for client:"


class _Firewall:
    """Collects iptables steps as (up, down) shell commands.

    Every step is defined once, so PostDown is derived from PostUp (in reverse
    order) and the two can never drift apart. Down commands tolerate rules that
    are already gone, so a partly-failed `wg-quick up` can still be torn down.
    """

    def __init__(self):
        self.steps = []

    def rule(self, chain, spec, table=None, in_own_chain=False):
        """Append a rule. Rules inside one of our own chains need no PostDown: the chain is flushed."""
        t = f" -t {table}" if table else ""
        down = None if in_own_chain else f"iptables{t} -D {chain} {spec} || true"
        self.steps.append((f"iptables{t} -A {chain} {spec}", down))

    def chain(self, name):
        self.steps.append((f"iptables -N {name} 2>/dev/null || iptables -F {name}",
                           f"iptables -F {name} 2>/dev/null; iptables -X {name} 2>/dev/null || true"))

    def hook(self, builtin_chain, spec):
        """Insert a jump at the top of a built-in chain (once), so it runs before distro firewall rules."""
        self.steps.append((f"iptables -C {builtin_chain} {spec} 2>/dev/null || iptables -I {builtin_chain} {spec}",
                           f"iptables -D {builtin_chain} {spec} || true"))

    def up(self):
        return [up for up, _ in self.steps]

    def down(self):
        return [down for _, down in reversed(self.steps) if down]


def chain_names(interface_name):
    return f"WGW-F-{interface_name}", f"WGW-I-{interface_name}"


def _build_firewall(client, public_interface):
    """NAT, DNAT and the isolation chains for one client.

    Isolation: everything that enters or leaves the client's WireGuard
    interface is sent through two per-client chains that end in DROP.
    - FORWARD chain: only the DNAT'd flows to the configured target ports (and
      their replies) are allowed; in full-tunnel mode the client may also reach
      the internet. Traffic to or from other clients' interfaces is dropped,
      and no global FORWARD policy change is needed.
    - INPUT chain: the client may only ping the VPS and receive replies, so it
      cannot reach services listening on the VPS itself.
    """
    iface = client['interface_name']
    pub = public_interface
    subnet = str(ipaddress.ip_interface(client['server_address']).network)
    client_ip = client_ip_for(client['server_address'])
    forward_chain, input_chain = chain_names(iface)
    fw = _Firewall()

    if client.get('full_tunnel', False):
        fw.rule("POSTROUTING", f"-s {subnet} -o {pub} -j MASQUERADE", table="nat")
    else:
        # Reverse-proxy case: masquerade so replies from the client return via the tunnel.
        fw.rule("POSTROUTING", f"-o {iface} -j MASQUERADE", table="nat")

    for rule in client['rules']:
        fw.rule("PREROUTING",
                f"-i {pub} -p {rule['protocol']} --dport {rule['public_port']} "
                f"-j DNAT --to-destination {rule['target_ip']}:{rule['target_port']}", table="nat")

    fw.chain(forward_chain)
    for rule in client['rules']:
        fw.rule(forward_chain,
                f"-i {pub} -o {iface} -p {rule['protocol']} -d {client_ip} --dport {rule['target_port']} "
                f"-m conntrack --ctstate DNAT -j ACCEPT", in_own_chain=True)
    if client.get('full_tunnel', False):
        fw.rule(forward_chain, f"-i {iface} -o {pub} -j ACCEPT", in_own_chain=True)
    else:
        fw.rule(forward_chain, f"-i {iface} -o {pub} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", in_own_chain=True)
    fw.rule(forward_chain, f"-i {pub} -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", in_own_chain=True)
    fw.rule(forward_chain, "-j DROP", in_own_chain=True)
    fw.hook("FORWARD", f"-i {iface} -j {forward_chain}")
    fw.hook("FORWARD", f"-o {iface} -j {forward_chain}")

    fw.chain(input_chain)
    fw.rule(input_chain, "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", in_own_chain=True)
    fw.rule(input_chain, "-p icmp -j ACCEPT", in_own_chain=True)
    fw.rule(input_chain, "-j DROP", in_own_chain=True)
    fw.hook("INPUT", f"-i {iface} -j {input_chain}")
    return fw


def generate_wg_config_for_client(client_data, public_interface):
    """Generates the server-side WireGuard config content for a client.

    Raises ValueError if any value is unsafe to place in a root-executed hook.
    """
    validate_public_interface(public_interface)
    validate_client(client_data)
    firewall = _build_firewall(client_data, public_interface)

    content = [
        f"{MANAGED_HEADER} {client_data['name']}",
        "[Interface]",
        f"Address = {client_data['server_address']}",
        f"ListenPort = {client_data['listen_port']}",
        f"PrivateKey = {client_data['server_private_key']}",
        "",
        "# --- NAT, port forwarding (DNAT) and per-client isolation; PostDown mirrors PostUp in reverse ---",
    ]
    content.extend(f"PostUp = {cmd}" for cmd in firewall.up())
    content.extend(f"PostDown = {cmd}" for cmd in firewall.down())

    if client_data['rules']:
        content.append("")
        content.append("# Forwarded ports:")
        for rule in client_data['rules']:
            content.append(f"#   {rule.get('comment', 'Rule')} ({rule['protocol'].upper()} {rule['public_port']} -> {rule['target_ip']}:{rule['target_port']})")

    content.extend([
        "", "[Peer]", f"# Client: {client_data['name']}",
        f"PublicKey = {client_data['client_public_key']}",
        f"AllowedIPs = {client_data['client_allowed_ips']}"
    ])
    return "\n".join(content)


CLIENT_KEY_PLACEHOLDER = "<YOUR_CLIENT_PRIVATE_KEY>"
ENDPOINT_PLACEHOLDER = "<YOUR_SERVER_PUBLIC_IP>"


def render_client_config(client, server_public_key, client_private_key, endpoint_host):
    """The config the client machine needs.

    `client_private_key` is None when the client generated its own keypair and
    only supplied the public half; a placeholder is shown instead.
    """
    interface = ipaddress.ip_interface(client['server_address'])
    full_tunnel = client.get('full_tunnel', False)
    lines = [
        "[Interface]",
        f"Address = {client_ip_for(client['server_address'])}/{interface.network.prefixlen}",
        f"PrivateKey = {client_private_key or CLIENT_KEY_PLACEHOLDER}",
    ]
    if full_tunnel:
        lines.append("DNS = 1.1.1.1")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_public_key}",
        f"Endpoint = {endpoint_host}:{client['listen_port']}",
        f"AllowedIPs = {'0.0.0.0/0' if full_tunnel else interface.network}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"
