import json
import os

from .system import get_default_public_interface


def load_config(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f: return json.load(f)
    return {"public_interface": get_default_public_interface(), "clients": []}


def save_config(filepath, data):
    with open(filepath, 'w') as f: json.dump(data, f, indent=4)
