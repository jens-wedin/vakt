"""The detector → renderer contract.

alerts.render() falls back to the raw message when an event's detail is missing
a key it needs — silently, by design. These tests make sure the detectors
actually hand over what the renderers ask for, so the fallback stays a safety
net instead of becoming the normal path.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import config  # noqa: E402

config.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")  # before store connects
config.DASHBOARD_URL = "http://vakt.local:8181"

import alerts  # noqa: E402
import detect  # noqa: E402
import store  # noqa: E402


def client(mac, name, ip, network, wired=False):
    return {"mac": mac, "hostname": name, "ip": ip, "network": network,
            "is_wired": wired, "rx_bytes": 0, "tx_bytes": 0}


class ClientEvents(unittest.TestCase):
    def setUp(self):
        store.set_meta("baseline_done", "1")  # skip the silent first run

    def test_new_device_renders_as_a_human_notification(self):
        events = detect.process_clients(
            [client("aa:bb:cc:dd:ee:01", "Galaxy-S23", "192.168.1.94", "Default")])
        [e] = [e for e in events if e["kind"] == "new_device"]
        r = alerts.render(e)
        self.assertEqual(r["title"], "New device on Default")
        self.assertIn("Galaxy-S23 · Wi-Fi · 192.168.1.94", r["body"])

    def test_network_change_renders_with_the_previous_network(self):
        detect.process_clients(
            [client("aa:bb:cc:dd:ee:02", "Dishwasher", "192.168.1.51", "Default")])
        events = detect.process_clients(
            [client("aa:bb:cc:dd:ee:02", "Dishwasher", "192.168.10.51", "IoT")])
        [e] = [e for e in events if e["kind"] == "network_change"]
        r = alerts.render(e)
        self.assertEqual(r["title"], "Dishwasher switched to IoT")
        self.assertIn("Previously on Default", r["body"])


class ConfigEvents(unittest.TestCase):
    def _rule(self, enabled):
        return {"firewallrule": [{"_id": "fw1", "name": "Block new IoT → Trusted",
                                  "enabled": enabled, "ruleset": "LAN_IN"}]}

    def test_config_change_renders_the_diff_in_words(self):
        detect.process_config(self._rule(True))          # baseline
        events = detect.process_config(self._rule(False))
        [e] = [e for e in events if e["kind"] == "config_changed"]
        r = alerts.render(e)
        self.assertEqual(r["title"], "Firewall rule changed")
        self.assertIn('"Block new IoT → Trusted"', r["body"])
        self.assertIn("Turned off (was on)", r["body"])
        self.assertEqual(r["priority"], "high")

    def test_the_dashboard_message_is_readable_too(self):
        detect.process_config({"wlanconf": [{"_id": "w1", "name": "manfred",
                                             "x_passphrase": "hunter2"}]})
        events = detect.process_config({"wlanconf": [{"_id": "w1", "name": "manfred",
                                                      "x_passphrase": "swordfish"}]})
        [e] = [e for e in events if e["kind"] == "config_changed"]
        self.assertIn("Wi-Fi passphrase changed", e["message"])
        self.assertNotIn("hunter2", e["message"])
        self.assertNotIn("swordfish", e["message"])


if __name__ == "__main__":
    unittest.main()
