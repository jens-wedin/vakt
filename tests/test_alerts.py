"""Notification rendering tests. Run: .venv/bin/python -m unittest discover -s tests"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import alerts  # noqa: E402
import config  # noqa: E402
import detect  # noqa: E402

DASH = "http://vakt.local:8181"


def ev(kind, severity, message="raw message", /, **detail):
    """An event as store.add_event() returns it. Positional-only so that a
    detail key of its own named `kind` (Protect devices have one) can't
    collide with this helper's parameters."""
    return {"ts": "2026-09-20T19:14:03Z", "kind": kind, "severity": severity,
            "mac": detail.get("mac"), "message": message, "detail": detail}


class NewDevice(unittest.TestCase):
    def setUp(self):
        config.DASHBOARD_URL = DASH

    def _stranger(self, network="Default", severity="critical"):
        return alerts.render(ev("new_device", severity, name="Galaxy-S23",
                                mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.94",
                                network=network, link="Wi-Fi"))

    def test_title_names_the_network_it_joined(self):
        self.assertEqual(self._stranger()["title"], "New device on Default")

    def test_body_leads_with_device_link_and_ip(self):
        self.assertIn("Galaxy-S23 · Wi-Fi · 192.168.1.94", self._stranger()["body"])

    def test_body_carries_the_mac_for_lookup(self):
        self.assertIn("aa:bb:cc:dd:ee:ff", self._stranger()["body"])

    def test_body_says_why_it_alerted(self):
        self.assertIn("Never seen before", self._stranger()["body"])

    def test_device_without_ip_says_so_instead_of_leaving_a_gap(self):
        r = alerts.render(ev("new_device", "critical", name="thing", mac="a:b",
                             ip="", network="IoT", link="Wi-Fi"))
        self.assertIn("no IP yet", r["body"])


class Severity(unittest.TestCase):
    def setUp(self):
        config.DASHBOARD_URL = DASH

    def test_critical_gets_siren_plus_kind_tag_and_high_priority(self):
        r = alerts.render(ev("new_device", "critical", name="x", mac="a:b",
                             ip="1.2.3.4", network="Default", link="Wi-Fi"))
        self.assertEqual(r["tags"], "rotating_light,new")
        self.assertEqual(r["priority"], "high")

    def test_warning_gets_kind_tag_only_and_default_priority(self):
        r = alerts.render(ev("new_device", "warning", name="x", mac="a:b",
                             ip="1.2.3.4", network="IoT", link="Wi-Fi"))
        self.assertEqual(r["tags"], "new")
        self.assertEqual(r["priority"], "default")


class OtherKinds(unittest.TestCase):
    def setUp(self):
        config.DASHBOARD_URL = DASH

    def test_network_change_titles_the_move_and_names_the_old_network(self):
        r = alerts.render(ev("network_change", "warning", name="Dishwasher",
                             mac="7c:2e:bd:44:19:03", ip="192.168.10.51",
                             network="IoT", prev_network="Default", link="Wi-Fi"))
        self.assertEqual(r["title"], "Dishwasher switched to IoT")
        self.assertIn("Previously on Default", r["body"])

    def test_traffic_anomaly_shows_rate_against_its_own_normal(self):
        r = alerts.render(ev("traffic_anomaly", "critical", name="espressif",
                             mac="a:b", ip="192.168.10.72", network="IoT",
                             rate_mbps=14.2, baseline_mbps=0.31, minutes=12))
        self.assertEqual(r["title"], "Unusual upload from espressif")
        self.assertIn("14.2 Mbit/s for 12 min", r["body"])
        self.assertIn("Normally 0.31 Mbit/s", r["body"])

    def test_protect_down_names_the_device_and_its_kind(self):
        r = alerts.render(ev("protect_down", "critical", name="Front Door",
                             kind="sensor", state="DISCONNECTED"))
        self.assertEqual(r["title"], "Front Door sensor offline")
        self.assertIn("DISCONNECTED", r["body"])

    def test_protect_title_avoids_repeating_the_kind(self):
        r = alerts.render(ev("protect_down", "critical", name="Garage Camera",
                             kind="camera", state="OFFLINE"))
        self.assertEqual(r["title"], "Garage Camera offline")

    def test_config_change_quotes_the_rule_and_explains_it_in_words(self):
        r = alerts.render(ev("config_changed", "critical", label="Firewall rule",
                             name="Block new IoT → Trusted",
                             changes=["Turned off (was on)"], more=0))
        self.assertEqual(r["title"], "Firewall rule changed")
        self.assertIn('"Block new IoT → Trusted"', r["body"])
        self.assertIn("Turned off (was on)", r["body"])

    def test_config_change_counts_the_fields_it_left_out(self):
        r = alerts.render(ev("config_changed", "warning", label="WLAN", name="manfred",
                             changes=["a", "b", "c"], more=2))
        self.assertIn("+2 more", r["body"])

    def test_config_removed_says_removed(self):
        r = alerts.render(ev("config_removed", "critical", label="NAT rule",
                             name="hairpin", changes=[], more=0))
        self.assertEqual(r["title"], "NAT rule removed")

    def test_ips_alert_says_the_engine_fired_and_where_to_look(self):
        r = alerts.render(ev("ips_alert", "info", when="2026-09-20 08:14",
                             alert_id="6-2026-09-20T08:14:02"))
        self.assertEqual(r["title"], "IPS logged an alert")
        self.assertIn("2026-09-20 08:14", r["body"])

    def test_poller_error_is_about_vakt_not_the_network(self):
        r = alerts.render(ev("poller_error", "warning", which="clients",
                             consecutive=5, error="timeout"))
        self.assertEqual(r["title"], "vakt lost contact with UniFi")
        self.assertIn("clients", r["body"])


class Fallback(unittest.TestCase):
    """An event with no detail must still push — never swallow an alert."""

    def setUp(self):
        config.DASHBOARD_URL = DASH

    def test_unknown_kind_falls_back_to_the_raw_message(self):
        r = alerts.render({"ts": "t", "kind": "mystery", "severity": "warning",
                           "mac": None, "message": "something happened"})
        self.assertEqual(r["title"], "vakt: mystery")
        self.assertEqual(r["body"], "something happened")

    def test_broken_detail_falls_back_instead_of_losing_the_alert(self):
        # network_change detail with prev_network missing — the renderer raises.
        r = alerts.render(ev("network_change", "warning", "raw text", name="x",
                             mac="a:b", ip="1.2.3.4", network="IoT", link="Wi-Fi"))
        self.assertEqual(r["body"], "raw text")
        self.assertEqual(r["tags"], "arrows_counterclockwise")

    def test_known_kind_without_detail_falls_back_too(self):
        r = alerts.render({"ts": "t", "kind": "new_device", "severity": "critical",
                           "mac": None, "message": "raw text"})
        self.assertEqual(r["body"], "raw text")


class DashboardLink(unittest.TestCase):
    def _render(self):
        return alerts.render(ev("new_device", "critical", name="x", mac="a:b",
                                ip="1.2.3.4", network="Default", link="Wi-Fi"))

    def test_link_configured_adds_click_target_and_invites_the_tap(self):
        config.DASHBOARD_URL = DASH
        r = self._render()
        self.assertEqual(r["click"], DASH)
        self.assertIn("tap to review", r["body"].lower())

    def test_no_link_configured_drops_both(self):
        config.DASHBOARD_URL = ""
        r = self._render()
        self.assertEqual(r["click"], "")
        self.assertNotIn("tap", r["body"].lower())


class HumanizeConfigChange(unittest.TestCase):
    def test_enabled_flag_reads_as_turned_on_or_off(self):
        self.assertEqual(detect.humanize_change("enabled", True, False),
                         "Turned off (was on)")
        self.assertEqual(detect.humanize_change("enabled", False, True),
                         "Turned on (was off)")

    def test_secret_fields_report_the_change_never_the_value(self):
        line = detect.humanize_change("x_passphrase", "sha256:aaaa", "sha256:bbbb")
        self.assertEqual(line, "Wi-Fi passphrase changed")
        self.assertNotIn("sha256", line)

    def test_plain_field_reads_as_a_sentence_without_json_quoting(self):
        self.assertEqual(detect.humanize_change("rule_index", "20000", "20001"),
                         "Rule index: 20000 → 20001")

    def test_empty_value_is_spelled_out(self):
        self.assertEqual(detect.humanize_change("dst_address", None, "192.168.1.27"),
                         "Dst address: (none) → 192.168.1.27")


if __name__ == "__main__":
    unittest.main()
