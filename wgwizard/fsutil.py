import os
import tempfile


def write_private_file(path, text, mode=0o600):
    """Atomically write `text` to `path`, never exposing it with wider permissions.

    The data goes to a 0600 temp file in the same directory, is fsynced, and
    then renamed over the target, so readers see either the old or the new
    content and a crash cannot leave a half-written file.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try: os.unlink(tmp_path)
        except OSError: pass
        raise
