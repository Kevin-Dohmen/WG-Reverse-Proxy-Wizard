import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from wgwizard import actions, host, rendering, service
from wgwizard.store import Session
from tests.test_validation import KEY_A, KEY_B, sample_client

SRV_PRIV, SRV_PUB = "S" * 43 + "=", "P" * 43 + "="
CLI_PRIV, CLI_PUB = "C" * 43 + "=", "U" * 43 + "="


class ActionTestCase(unittest.TestCase):
    """Drives the interactive menu actions with scripted answers and a faked system."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "config.json")
        self.apply = mock.Mock(return_value=True)
        self.keypairs = mock.Mock(side_effect=[(SRV_PRIV, SRV_PUB), (CLI_PRIV, CLI_PUB)])
        for target, new in {
            "apply_client_config": self.apply,
            "generate_keypair": self.keypairs,
            "get_public_ip": mock.Mock(return_value="203.0.113.5"),
            "local_ipv4_networks": mock.Mock(return_value=[]),
            "ensure_interface_unused": mock.Mock(),
            "interface_status": mock.Mock(return_value="up"),
        }.items():
            p = mock.patch.object(actions, target, new)
            p.start()
            self.addCleanup(p.stop)

    def session(self, clients=()):
        session = Session(self.path)
        session.config = {"public_interface": "eth0", "clients": list(clients)}
        return session

    def run_action(self, func, session, answers):
        feed = iter(answers)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("builtins.input", side_effect=lambda prompt="": next(feed)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            func(session)
        self.assertEqual(list(feed), [], "unused scripted answers")
        return out.getvalue(), err.getvalue()

    def saved(self):
        with open(self.path) as f: return json.load(f)


class AddClient(ActionTestCase):
    ANSWERS = ["web", "", "10.50.1.1/24", "", "51820",
               "y", "", "", "8080", "", "n",   # one rule with defaults, then stop
               "n"]                            # not a full tunnel

    def test_add_with_generated_keys_saves_config(self):
        session = self.session()
        out, _ = self.run_action(actions.add_new_client, session, self.ANSWERS + ["n"])
        client = session.config["clients"][0]
        self.assertEqual((client["name"], client["interface_name"], client["server_address"]), ("web", "wg0", "10.50.1.1/24"))
        self.assertEqual(client["client_allowed_ips"], "10.50.1.2/32")
        self.assertEqual(client["rules"][0]["target_ip"], "10.50.1.2")
        self.assertEqual(client["rules"][0]["target_port"], 8080)
        self.assertEqual(self.saved()["clients"][0]["name"], "web")
        self.assertIn(f"PrivateKey = {CLI_PRIV}", out)
        self.assertIn("Endpoint = 203.0.113.5:51820", out)
        with open(self.path) as f: self.assertNotIn(CLI_PRIV, f.read())

    def test_client_supplied_public_key_means_no_private_key_here(self):
        supplied = "K" * 43 + "="
        session = self.session()
        answers = list(self.ANSWERS)
        answers[3] = supplied
        self.keypairs.side_effect = [(SRV_PRIV, SRV_PUB)]
        out, _ = self.run_action(actions.add_new_client, session, answers)
        self.assertEqual(self.keypairs.call_count, 1)
        self.assertEqual(session.config["clients"][0]["client_public_key"], supplied)
        self.assertIn(rendering.CLIENT_KEY_PLACEHOLDER, out)

    def test_bad_answers_are_reprompted_not_fatal(self):
        session = self.session()
        answers = ["bad name!", "web", "wg0; reboot", "wg0", "10.50.1.1", "10.50.1.1/24", "not-a-key", "",
                   "abc", "70000", "51820", "n", "n"]
        _, err = self.run_action(actions.add_new_client, session, answers + ["n"])
        self.assertEqual(session.config["clients"][0]["listen_port"], 51820)
        for expected in ("name must be", "interface name must", "prefix length", "not a valid WireGuard key", "not a number", "between 1 and 65535"):
            self.assertIn(expected, err)

    def test_clashes_with_existing_clients_are_refused(self):
        existing = sample_client(name="web", interface_name="wg0", listen_port=51820, server_address="10.50.1.1/24",
                                 client_allowed_ips="10.50.1.2/32", rules=[])
        session = self.session([existing])
        answers = ["web", "other", "wg0", "wg1", "10.50.1.1/24", "10.50.2.1/24", "", "51820", "51821", "n", "n", "n"]
        _, err = self.run_action(actions.add_new_client, session, answers)
        for expected in ("already exists", "already used by another client", "overlaps the subnet", "UDP port 51820"):
            self.assertIn(expected, err)
        self.assertEqual([c["name"] for c in session.config["clients"]], ["web", "other"])

    def test_failed_apply_adds_nothing_and_saves_nothing(self):
        self.apply.return_value = False
        session = self.session()
        self.run_action(actions.add_new_client, session, self.ANSWERS)
        self.assertEqual(session.config["clients"], [])
        self.assertFalse(os.path.exists(self.path))

    def test_saving_client_config_to_file(self):
        target = os.path.join(self.dir.name, "web.conf")
        session = self.session()
        self.run_action(actions.add_new_client, session, self.ANSWERS + ["y", target])
        with open(target) as f: text = f.read()
        self.assertIn(f"PrivateKey = {CLI_PRIV}", text)
        if os.name != "nt": self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)


class EditAndRemove(ActionTestCase):
    def setUp(self):
        super().setUp()
        self.client = sample_client()

    def test_edit_applies_once_with_previous_and_saves(self):
        session = self.session([self.client])
        # select client 1, change listen port, apply
        self.run_action(actions.edit_existing_client, session, ["1", "4", "60000", "7"])
        self.assertEqual(self.apply.call_count, 1)
        _, kwargs = self.apply.call_args
        self.assertEqual(kwargs["previous"]["listen_port"], 58249)
        self.assertEqual(self.saved()["clients"][0]["listen_port"], 60000)

    def test_failed_edit_keeps_original_and_allows_discard(self):
        self.apply.return_value = False
        session = self.session([self.client])
        original = json.loads(json.dumps(self.client))
        self.run_action(actions.edit_existing_client, session, ["1", "4", "60000", "7", "8"])
        self.assertEqual(session.config["clients"][0], original)
        self.assertFalse(os.path.exists(self.path))

    def test_discard_and_no_op_do_not_apply(self):
        session = self.session([self.client])
        self.run_action(actions.edit_existing_client, session, ["1", "4", "60000", "8"])
        self.run_action(actions.edit_existing_client, session, ["1", "7"])
        self.apply.assert_not_called()

    def test_subnet_change_updates_derived_fields(self):
        session = self.session([self.client])
        self.run_action(actions.edit_existing_client, session, ["1", "3", "10.77.0.1/24", "7"])
        client = session.config["clients"][0]
        self.assertEqual(client["client_allowed_ips"], "10.77.0.2/32")
        self.assertEqual(client["rules"][0]["target_ip"], "10.77.0.2")

    def test_add_and_remove_single_rules(self):
        session = self.session([self.client])
        # rules menu: add a udp rule, remove rule 1, back, apply
        self.run_action(actions.edit_existing_client, session,
                        ["1", "6", "1", "Voice", "udp", "9000", "", "2", "1", "3", "7"])
        rules = session.config["clients"][0]["rules"]
        self.assertEqual([(r["protocol"], r["public_port"]) for r in rules], [("udp", 9000)])

    def test_remove_client(self):
        session = self.session([self.client])
        with mock.patch.object(actions, "remove_client_config", return_value=True) as remove:
            self.run_action(actions.remove_client, session, ["1", "y"])
        remove.assert_called_once()
        self.assertEqual(self.saved()["clients"], [])

    def test_remove_declined(self):
        session = self.session([self.client])
        with mock.patch.object(actions, "remove_client_config") as remove:
            self.run_action(actions.remove_client, session, ["1", "n"])
        remove.assert_not_called()
        self.assertEqual(len(session.config["clients"]), 1)


class ClientConfigAndStatus(unittest.TestCase):
    def test_split_tunnel_client_config(self):
        text = rendering.render_client_config(sample_client(), SRV_PUB, CLI_PRIV, "203.0.113.5")
        self.assertIn("Address = 10.123.8.2/24", text)
        self.assertIn("AllowedIPs = 10.123.8.0/24", text)
        self.assertNotIn("DNS", text)

    def test_full_tunnel_client_config(self):
        text = rendering.render_client_config(sample_client(full_tunnel=True), SRV_PUB, None, "vpn.example.org")
        self.assertIn("AllowedIPs = 0.0.0.0/0", text)
        self.assertIn("DNS = 1.1.1.1", text)
        self.assertIn(rendering.CLIENT_KEY_PLACEHOLDER, text)
        self.assertIn("Endpoint = vpn.example.org:58249", text)

    def test_format_age(self):
        self.assertEqual([host.format_age(s) for s in (5, 90, 7300, 200000)], ["5s", "1m", "2h", "2d"])

    def test_interface_status(self):
        with mock.patch.object(host, "interface_exists", return_value=False):
            self.assertEqual(host.interface_status("wg0"), "down")
        with mock.patch.object(host, "interface_exists", return_value=True), \
                mock.patch.object(host.subprocess, "run") as run:
            run.return_value.stdout = "PUBKEY\t1000\n"
            self.assertEqual(host.interface_status("wg0", now=1014), "up, last handshake 14s ago")
            run.return_value.stdout = "PUBKEY\t0\n"
            self.assertEqual(host.interface_status("wg0"), "up, no handshake yet")
            run.side_effect = FileNotFoundError
            self.assertEqual(host.interface_status("wg0"), "up")


class InterruptedApply(unittest.TestCase):
    def test_ctrl_c_during_start_rolls_back(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(service, "WG_DIR", d), mock.patch.object(service, "check_root"):
            calls = []

            def fake(action, iface, quiet=False):
                calls.append(action)
                if action == "start" and calls.count("start") == 1:
                    raise KeyboardInterrupt
                return True
            with mock.patch.object(service, "manage_service", side_effect=fake), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    service.apply_client_config(sample_client(), "eth0")
            self.assertIsNone(service.read_conf("wg0"))
            self.assertIn("disable", calls)


if __name__ == "__main__":
    unittest.main()
