import re
import unittest

from wgwizard.rendering import MANAGED_HEADER, generate_wg_config_for_client
from tests.test_validation import sample_client


def hooks(text, kind):
    return [line.split(" = ", 1)[1] for line in text.splitlines() if line.startswith(f"{kind} = ")]


class FirewallRendering(unittest.TestCase):
    def render(self, **overrides):
        return generate_wg_config_for_client(sample_client(**overrides), "eth0")

    def test_starts_with_managed_header_and_has_peer(self):
        text = self.render()
        self.assertTrue(text.startswith(MANAGED_HEADER))
        self.assertIn("[Peer]", text)
        self.assertIn("AllowedIPs = 10.123.8.2/32", text)

    def test_dnat_rule_and_matching_forward_accept(self):
        text = self.render()
        up = hooks(text, "PostUp")
        self.assertIn("iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 25565 -j DNAT --to-destination 10.123.8.2:25565", up)
        self.assertIn("iptables -A WGW-F-wg0 -i eth0 -o wg0 -p tcp -d 10.123.8.2 --dport 25565 -m conntrack --ctstate DNAT -j ACCEPT", up)

    def test_every_post_up_has_a_post_down_counterpart(self):
        for overrides in ({}, {"full_tunnel": True}, {"rules": []}):
            text = self.render(**overrides)
            up, down = hooks(text, "PostUp"), hooks(text, "PostDown")
            # Every rule outside our own chains must be deleted again, with the same spec.
            for cmd in up:
                m = re.match(r"iptables( -t nat)? -A (\S+) (.*)$", cmd)
                if m and not m.group(2).startswith("WGW-"):
                    expected = f"iptables{m.group(1) or ''} -D {m.group(2)} {m.group(3)} || true"
                    self.assertIn(expected, down)
            # Hooks are removed, and chains flushed and deleted.
            for chain in ("WGW-F-wg0", "WGW-I-wg0"):
                self.assertTrue(any(f"-F {chain}" in d and f"-X {chain}" in d for d in down))
            self.assertTrue(all(d.endswith("|| true") for d in down))

    def test_teardown_removes_hooks_before_deleting_chains(self):
        down = hooks(self.render(), "PostDown")
        jump = next(i for i, d in enumerate(down) if d.startswith("iptables -D FORWARD -i wg0"))
        flush = next(i for i, d in enumerate(down) if "-X WGW-F-wg0" in d)
        self.assertLess(jump, flush)

    def test_chains_are_created_before_use_and_idempotently(self):
        up = hooks(self.render(), "PostUp")
        create = next(i for i, c in enumerate(up) if c.startswith("iptables -N WGW-F-wg0"))
        first_use = next(i for i, c in enumerate(up) if c.startswith("iptables -A WGW-F-wg0"))
        hook = next(i for i, c in enumerate(up) if "-I FORWARD" in c)
        self.assertLess(create, first_use)
        self.assertLess(first_use, hook)
        self.assertIn("|| iptables -F WGW-F-wg0", up[create])
        self.assertTrue(all("iptables -C" in c for c in up if " -I " in c))

    def test_split_tunnel_blocks_client_originated_traffic_and_other_clients(self):
        up = hooks(self.render(), "PostUp")
        self.assertIn("iptables -A WGW-F-wg0 -j DROP", up)
        self.assertIn("iptables -A WGW-I-wg0 -j DROP", up)
        self.assertNotIn("iptables -A WGW-F-wg0 -i wg0 -o eth0 -j ACCEPT", up)
        self.assertIn("iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE", up)
        # No global ACCEPT of forwarded traffic: isolation must not depend on FORWARD policy.
        self.assertFalse([c for c in up if re.match(r"iptables -[AI] FORWARD .*-j ACCEPT", c)])

    def test_full_tunnel_allows_outbound_but_still_isolates(self):
        up = hooks(self.render(full_tunnel=True), "PostUp")
        self.assertIn("iptables -A WGW-F-wg0 -i wg0 -o eth0 -j ACCEPT", up)
        self.assertIn("iptables -t nat -A POSTROUTING -s 10.123.8.0/24 -o eth0 -j MASQUERADE", up)
        self.assertIn("iptables -A WGW-F-wg0 -j DROP", up)
        drop = up.index("iptables -A WGW-F-wg0 -j DROP")
        self.assertEqual(max(i for i, c in enumerate(up) if c.startswith("iptables -A WGW-F-wg0")), drop)

    def test_each_client_gets_its_own_chains(self):
        other = generate_wg_config_for_client(sample_client(interface_name="wg3"), "eth0")
        self.assertIn("WGW-F-wg3", other)
        self.assertNotIn("WGW-F-wg0", other)


if __name__ == "__main__":
    unittest.main()
