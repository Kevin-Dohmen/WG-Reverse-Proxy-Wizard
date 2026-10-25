import sys


def get_input(prompt, default=None, required=True):
    prompt_text = f"{prompt}"
    if default is not None: prompt_text += f" [{default}]"
    prompt_text += ": "
    while True:
        user_input = input(prompt_text).strip()
        if user_input: return user_input
        if default is not None: return str(default)
        if required: print("Error: This field is required.", file=sys.stderr)
        else: return ""


def ask(prompt, default=None, validate=None, required=True):
    """Prompt until `validate` (which raises ValueError on bad input) accepts the answer."""
    while True:
        raw = get_input(prompt, default, required)
        if validate is None: return raw
        try:
            return validate(raw)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)


def confirm(prompt, default=False):
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{prompt} [{hint}]: ").strip().lower()
        if not answer: return default
        if answer in ("y", "yes"): return True
        if answer in ("n", "no"): return False
        print("Please answer 'y' or 'n'.", file=sys.stderr)
