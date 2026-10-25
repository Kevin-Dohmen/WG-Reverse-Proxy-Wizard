import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest import mock

from wgwizard import service
from tests.test_validation import sample_client


class ApplyClientConfig(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.calls = []
        self.failing = set()  # (action, interface) pairs that should fail
        patches = [
            mock.patch.object(service, "WG_DIR", self.dir.name),
            mock.patch.object(service, "check_root"),
            mock.patch.object(service, "manage_service", side_effect=self.fake_service),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def fake_service(self, action, iface, quiet=False):
        # Record what the conf looked like when each action ran.
        self.calls.append((action, iface, service.read_conf(iface)))
        return (action, iface) not in self.failing

    def apply(self, client, previous=None):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            return service.apply_client_config(client, "eth0", previous=previous)

    def write_live(self, client):
        text = service.generate_wg_config_for_client(client, "eth0")
        with open(service.conf_path(client["interface_name"]), "w") as f: f.write(text)
        return text

    def test_old_interface_is_stopped_while_old_conf_is_still_on_disk(self):
        old = sample_client()
        old_text = self.write_live(old)
        new = sample_client(listen_port=12345)
        self.assertTrue(self.apply(new, previous=old))
        self.assertEqual(self.calls[0], ("stop", "wg0", old_text))
        self.assertEqual([c[0] for c in self.calls], ["stop", "enable", "start"])
        self.assertIn("ListenPort = 12345", service.read_conf("wg0"))

    def test_failed_start_restores_previous_conf_and_restarts_it(self):
        old = sample_client()
        old_text = self.write_live(old)
        self.failing.add(("start", "wg0"))
        # The restore also calls start, which keeps failing here; the conf must still be restored.
        self.assertFalse(self.apply(sample_client(listen_port=12345), previous=old))
        self.assertEqual(service.read_conf("wg0"), old_text)

    def test_failed_start_of_new_client_leaves_no_conf_behind(self):
        self.failing.add(("start", "wg0"))
        self.assertFalse(self.apply(sample_client()))
        self.assertIsNone(service.read_conf("wg0"))
        self.assertIn(("disable", "wg0"), [(c[0], c[1]) for c in self.calls])

    def test_failed_stop_changes_nothing(self):
        old = sample_client()
        old_text = self.write_live(old)
        self.failing.add(("stop", "wg0"))
        self.assertFalse(self.apply(sample_client(listen_port=12345), previous=old))
        self.assertEqual(service.read_conf("wg0"), old_text)
        self.assertEqual([c[0] for c in self.calls], ["stop"])

    def test_interface_rename_removes_old_conf(self):
        old = sample_client()
        self.write_live(old)
        self.assertTrue(self.apply(sample_client(interface_name="wg7"), previous=old))
        self.assertIsNone(service.read_conf("wg0"))
        self.assertIsNotNone(service.read_conf("wg7"))
        self.assertEqual(self.calls[0][:2], ("stop", "wg0"))

    def test_failed_rename_restores_old_interface(self):
        old = sample_client()
        old_text = self.write_live(old)
        self.failing.add(("start", "wg7"))
        self.assertFalse(self.apply(sample_client(interface_name="wg7"), previous=old))
        self.assertIsNone(service.read_conf("wg7"))
        self.assertEqual(service.read_conf("wg0"), old_text)

    def test_conf_files_are_private(self):
        self.assertTrue(self.apply(sample_client()))
        if os.name != "nt":
            self.assertEqual(os.stat(service.conf_path("wg0")).st_mode & 0o777, 0o600)

    def test_invalid_client_is_refused_before_touching_anything(self):
        self.assertFalse(self.apply(sample_client(interface_name="wg0; reboot")))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
