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
