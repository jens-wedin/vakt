"""Which optional integrations are wired up — reported as booleans so a
deployment can be verified without exposing a topic URL or a password."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import config  # noqa: E402

OPTIONAL = {"ntfy", "dashboard_url", "dashboard_password", "protect"}


class Configured(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(config, k) for k in
                       ("NTFY_URL", "DASHBOARD_URL", "DASHBOARD_PASSWORD",
                        "UNIFI_NVR_CONSOLE_ID")}

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(config, k, v)

    def test_set_value_reads_true_but_never_leaks_the_value(self):
        config.DASHBOARD_URL = "http://vakt.local:8181"
        config.NTFY_URL = "https://ntfy.sh/a-secret-topic-name"
        c = config.configured()
        self.assertIs(c["dashboard_url"], True)
        self.assertIs(c["ntfy"], True)
        self.assertNotIn("vakt.local", str(c))
        self.assertNotIn("secret-topic", str(c))

    def test_empty_value_reads_false(self):
        config.DASHBOARD_URL = ""
        self.assertIs(config.configured()["dashboard_url"], False)

    def test_covers_every_optional_integration(self):
        self.assertEqual(set(config.configured()), OPTIONAL)


if __name__ == "__main__":
    unittest.main()
