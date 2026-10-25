import json
import os
import tempfile
import unittest

from wgwizard import store, validation as v
from wgwizard.errors import ConfigError
from tests.test_validation import KEY_A, KEY_B, sample_client


def second_client(**overrides):
    client = sample_client(
        name="web", interface_name="wg1", listen_port=51000, server_address="10.45.12.1/24",
        client_allowed_ips="10.45.12.2/32",
        rules=[{"comment": "Web", "protocol": "tcp", "public_port": 80, "target_ip": "10.45.12.2", "target_port": 80}])
    client.update(overrides)
    return client


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = os.path.join(self.dir.name, "config.json")

    def write(self, data):
        with open(self.path, "w") as f: json.dump(data, f)

    def test_round_trip_and_backup(self):
        config = {"public_interface": "eth0", "clients": [sample_client()]}
        store.save_config(self.path, config)
        self.assertEqual(store.load_config(self.path), config)
        self.assertFalse(os.path.exists(self.path + ".bak"))
        config["clients"].append(second_client())
        store.save_config(self.path, config)
        with open(self.path + ".bak") as f:
            self.assertEqual(len(json.load(f)["clients"]), 1)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_saved_files_are_private(self):
        store.save_config(self.path, {"public_interface": "eth0", "clients": []})
        store.save_config(self.path, {"public_interface": "eth0", "clients": []})
        for path in (self.path, self.path + ".bak"):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_no_temp_files_left_behind(self):
        store.save_config(self.path, {"public_interface": "eth0", "clients": []})
        self.assertEqual(os.listdir(self.dir.name), ["config.json"])

    def test_corrupt_json_is_a_config_error(self):
        with open(self.path, "w") as f: f.write("{not json")
        with self.assertRaises(ConfigError): store.load_config(self.path)

    def test_invalid_client_is_reported_not_applied(self):
        self.write({"public_interface": "eth0", "clients": [sample_client(interface_name="wg0; reboot")]})
        with self.assertRaises(ConfigError) as ctx: store.load_config(self.path)
        self.assertIn("minecraft-server", str(ctx.exception))

    def test_bad_public_interface_is_rejected(self):
        self.write({"public_interface": "eth0; reboot", "clients": []})
        with self.assertRaises(ConfigError): store.load_config(self.path)

    @unittest.skipIf(store.fcntl is None, "needs fcntl")
    def test_second_instance_is_locked_out(self):
        self.write({"public_interface": "eth0", "clients": []})
        with store.Session(self.path):
            with self.assertRaises(ConfigError):
                store.Session(self.path).open()
        with store.Session(self.path):  # lock released on exit
            pass


class Conflicts(unittest.TestCase):
    def test_no_conflicts_between_distinct_clients(self):
        self.assertEqual(v.find_conflicts({"clients": [sample_client(), second_client()]}), [])

    def test_detects_every_kind_of_clash(self):
        clash = second_client(name="minecraft-server", interface_name="wg0", listen_port=58249,
                              server_address="10.123.8.9/24", client_allowed_ips="10.123.8.10/32",
                              rules=[{"comment": "dup", "protocol": "tcp", "public_port": 25565,
                                      "target_ip": "10.123.8.10", "target_port": 1}])
        text = "\n".join(v.find_conflicts({"clients": [sample_client(), clash]}))
        for expected in ("named", "interface wg0", "overlaps the subnet", "UDP port 58249", "TCP port 25565"):
            self.assertIn(expected, text)

    def test_same_port_on_different_protocols_is_fine(self):
        udp = second_client(rules=[{"comment": "u", "protocol": "udp", "public_port": 25565,
                                    "target_ip": "10.45.12.2", "target_port": 25565}])
        self.assertEqual(v.find_conflicts({"clients": [sample_client(), udp]}), [])

    def test_udp_forward_cannot_shadow_a_wireguard_listen_port(self):
        with self.assertRaises(ValueError):
            v.check_public_port_free([sample_client()], "udp", 58249)
        v.check_public_port_free([sample_client()], "tcp", 58249)

    def test_listen_port_cannot_equal_udp_forward(self):
        udp = second_client(rules=[{"comment": "u", "protocol": "udp", "public_port": 40000,
                                    "target_ip": "10.45.12.2", "target_port": 1}])
        with self.assertRaises(ValueError): v.check_listen_port_free([udp], 40000)

    def test_subnet_overlap_with_host_network(self):
        import ipaddress
        host = [ipaddress.ip_network("10.99.0.0/16")]
        with self.assertRaises(ValueError): v.check_subnet_free([], "10.99.5.1/24", host)
        v.check_subnet_free([], "10.98.5.1/24", host)


if __name__ == "__main__":
    unittest.main()
