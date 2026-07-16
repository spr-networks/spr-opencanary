import json
import logging
import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from spr_opencanary_filters import WebhookAlertFilter


def record(payload):
    return logging.LogRecord(
        name="spr-canary-01",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg=json.dumps(payload),
        args=(),
        exc_info=None,
    )


class WebhookAlertFilterTest(unittest.TestCase):
    def setUp(self):
        self.filter = WebhookAlertFilter()

    def test_suppresses_startup_service_registration(self):
        self.assertFalse(
            self.filter.filter(
                record(
                    {
                        "logtype": 1001,
                        "logdata": {
                            "msg": {
                                "logdata": "Added service from class CanarySSH"
                            }
                        },
                    }
                )
            )
        )

    def test_allows_attacker_events(self):
        self.assertTrue(self.filter.filter(record({"logtype": 4002})))
        self.assertTrue(self.filter.filter(record({"logtype": 99000})))

    def test_does_not_hide_unstructured_operational_errors(self):
        plain = logging.LogRecord(
            name="spr-canary-01",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="logger failed unexpectedly",
            args=(),
            exc_info=None,
        )
        self.assertTrue(self.filter.filter(plain))


if __name__ == "__main__":
    unittest.main()
