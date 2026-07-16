"""Logging filters applied only to outbound OpenCanary notifications."""

import json
import logging


class WebhookAlertFilter(logging.Filter):
    """Allow attacker events while suppressing OpenCanary lifecycle chatter."""

    def filter(self, record):
        try:
            payload = json.loads(record.getMessage())
            logtype = int(payload["logtype"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            # Do not hide unexpected operational messages that lack OpenCanary's
            # normal structured log envelope.
            return True

        return logtype >= 2000
