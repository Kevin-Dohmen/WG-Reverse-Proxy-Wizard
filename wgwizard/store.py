import json
import os
import shutil

from .errors import ConfigError, WizardError
from .fsutil import write_private_file
from .host import get_default_public_interface
from .validation import find_conflicts, validate_client, validate_public_interface

try:
    import fcntl
except ImportError:  # Windows: no advisory locking; the tool only manages Linux hosts anyway.
    fcntl = None


def load_config(filepath):
    if not os.path.exists(filepath):
        return {"public_interface": get_default_public_interface(), "clients": []}
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
    """Atomically replace the config file, keeping the previous version as <file>.bak."""
    if os.path.exists(filepath):
        shutil.copyfile(filepath, filepath + ".bak")
        os.chmod(filepath + ".bak", 0o600)
    write_private_file(filepath, json.dumps(data, indent=4) + "\n")


class Session:
    """The loaded config plus the exclusive lock that protects it.

    Only one wizard instance may manage a config at a time: two concurrent runs
    would each overwrite the other's changes (and each other's WireGuard confs).
    """

    def __init__(self, path):
        self.path = path
        self._lock_file = None

    def open(self):
        self._acquire_lock()
        try:
            self.config = load_config(self.path)
        except BaseException:
            self.close()
            raise
        return self

    def _acquire_lock(self):
        if fcntl is None: return
        self._lock_file = open(self.path + ".lock", "w")
        try:
            fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock_file.close()
            self._lock_file = None
            raise ConfigError(f"Another instance is already using {self.path} (lock file {self.path}.lock).") from None

    def close(self):
        if self._lock_file is not None:
            self._lock_file.close()
            self._lock_file = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    def conflicts(self):
        return find_conflicts(self.config)

    def save(self):
        """Persist the config; called after every change so disk never lags the live system."""
        try:
            save_config(self.path, self.config)
        except OSError as e:
            raise WizardError(
                f"The change was applied to the system but {self.path} could not be written ({e}). "
                "Fix the problem and run 'Re-apply all configurations' or edit the client again to save.") from e
