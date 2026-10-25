import json
import os

from .errors import ConfigError
from .fsutil import write_private_file
from .system import get_default_public_interface
from .validation import validate_client, validate_public_interface


def load_config(filepath):
    if not os.path.exists(filepath):
        return {"public_interface": get_default_public_interface() or "eth0", "clients": []}
    try:
        with open(filepath, 'r') as f: config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"Cannot read {filepath}: {e}") from e
    _validate_config(config, filepath)
    return config


def _validate_config(config, filepath):
    problems = []
    try:
        validate_public_interface(config['public_interface'])
        clients = config['clients']
        if not isinstance(clients, list): raise TypeError("'clients' must be a list")
    except (KeyError, TypeError, ValueError) as e:
        raise ConfigError(f"{filepath}: invalid top-level structure ({e})") from e
    for i, client in enumerate(clients, start=1):
        try:
            validate_client(client)
        except (ValueError, TypeError, AttributeError) as e:
            label = client.get('name', f'#{i}') if isinstance(client, dict) else f'#{i}'
            problems.append(f"  client {label}: {e}")
    if problems:
        raise ConfigError(f"{filepath} contains invalid data:\n" + "\n".join(problems))


def save_config(filepath, data):
    write_private_file(filepath, json.dumps(data, indent=4))
