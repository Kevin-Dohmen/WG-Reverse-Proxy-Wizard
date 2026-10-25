class WizardError(Exception):
    """A user-facing failure; the menu loop prints it and carries on."""


class ConfigError(WizardError):
    """The configuration file is unreadable or contains invalid data."""
