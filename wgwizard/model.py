import ipaddress
import random

from .errors import WizardError


def get_random_port(used_ports):
    while True:
        port = random.randint(49152, 65535)
        if port not in used_ports: return port


def get_random_subnet(taken_networks):
    """A random 10.x.y.1/24 that doesn't overlap any of the given networks."""
    for _ in range(10000):
        a, b = random.randint(0, 255), random.randint(0, 255)
        candidate = ipaddress.ip_network(f"10.{a}.{b}.0/24")
        if not any(candidate.overlaps(t) for t in taken_networks):
            return f"10.{a}.{b}.1/24"
    raise WizardError("Could not find a free 10.x.y.0/24 subnet.")


def get_next_interface_name(config):
    used_indices = {int(c['interface_name'][2:]) for c in config.get('clients', []) if c.get('interface_name', '').startswith('wg') and c['interface_name'][2:].isdigit()}
    next_index = 0
    while next_index in used_indices: next_index += 1
    return f"wg{next_index}"
