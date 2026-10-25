import copy
import unittest

from wgwizard import validation as v
from wgwizard.rendering import generate_wg_config_for_client

KEY_A = "A" * 43 + "="
KEY_B = "B" * 43 + "="


def sample_client(**overrides):
    client = {
        "name": "minecraft-server", "interface_name": "wg0", "listen_port": 58249,
        "server_address": "10.123.8.1/24", "server_private_key": KEY_A,
        "client_public_key": KEY_B, "client_allowed_ips": "10.123.8.2/32",
        "rules": [{"comment": "Minecraft", "protocol": "tcp", "public_port": 25565,
                   "target_ip": "10.123.8.2", "target_port": 25565}],
        "full_tunnel": False,
    }
    client.update(overrides)
    return client


class FieldValidators(unittest.TestCase):
    def test_protocol_is_normalised_and_restricted(self):
        self.assertEqual(v.validate_protocol(" TCP "), "tcp")
        for bad in ("icmp", "tcp; reboot", ""):
            with self.assertRaises(ValueError): v.validate_protocol(bad)

    def test_port_range(self):
        self.assertEqual(v.validate_port("65535"), 65535)
        for bad in ("0", "65536", "-1", "abc", ""):
            with self.assertRaises(ValueError): v.validate_port(bad)

    def test_interface_name_blocks_traversal_and_shell(self):
        self.assertEqual(v.validate_interface("wg12"), "wg12")
        for bad in ("../etc/passwd", "wg0;id", "eth0", "wg", "wg0 "):
            with self.assertRaises(ValueError): v.validate_interface(bad)

    def test_server_address(self):
        self.assertEqual(v.validate_server_address("10.1.2.1/24"), "10.1.2.1/24")
        for bad in ("10.1.2.1", "10.1.2.255/24", "10.1.2.1/8", "10.1.2.1/31", "fd00::1/64", "nope"):
            with self.assertRaises(ValueError, msg=bad): v.validate_server_address(bad)

    def test_client_ip_is_next_address(self):
        self.assertEqual(v.client_ip_for("10.1.2.1/24"), "10.1.2.2")

    def test_comment_rejects_control_characters(self):
        with self.assertRaises(ValueError): v.validate_comment("ok\nPostUp = reboot")


class ClientValidation(unittest.TestCase):
    def test_valid_client_passes(self):
        v.validate_client(sample_client())

    def test_rejects_injection_in_every_hook_field(self):
        bad_clients = [
            sample_client(interface_name="wg0; reboot"),
            sample_client(name="x\nPostUp = reboot"),
            sample_client(rules=[dict(sample_client()["rules"][0], protocol="tcp; reboot")]),
            sample_client(rules=[dict(sample_client()["rules"][0], comment="a\nPostUp = reboot")]),
            sample_client(rules=[dict(sample_client()["rules"][0], public_port="80; reboot")]),
        ]
        for client in bad_clients:
            with self.assertRaises(ValueError): v.validate_client(client)

    def test_rejects_stale_derived_fields(self):
        with self.assertRaises(ValueError): v.validate_client(sample_client(client_allowed_ips="10.9.9.2/32"))

    def test_rejects_missing_field(self):
        client = sample_client()
        del client["listen_port"]
        with self.assertRaises(ValueError): v.validate_client(client)

    def test_renderer_refuses_unsafe_client(self):
        with self.assertRaises(ValueError):
            generate_wg_config_for_client(sample_client(interface_name="wg0; reboot"), "eth0")
        with self.assertRaises(ValueError):
            generate_wg_config_for_client(sample_client(), "eth0; reboot")


if __name__ == "__main__":
    unittest.main()
