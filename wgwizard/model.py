import random


def get_random_port(used_ports):
    while True:
        port = random.randint(49152, 65535)
        if port not in used_ports: return port


def get_random_subnet(used_subnets):
    while True:
        subnet = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.1/24"
        if subnet not in used_subnets: return subnet


def get_next_interface_name(config):
    used_indices = {int(c['interface_name'][2:]) for c in config.get('clients', []) if c.get('interface_name', '').startswith('wg') and c['interface_name'][2:].isdigit()}
    next_index = 0
    while next_index in used_indices: next_index += 1
    return f"wg{next_index}"
