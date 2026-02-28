"""
Notification backends for alerting on new findings.

Supported:
  - Slack webhook
  - Discord webhook
  - Plain text log file (always on)

Notifications fire on new findings above a configured severity threshold.
"""

import json
import logging
import requests
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    sev = SEVERITY_ORDER.get((severity or "info").lower(), 0)
    thr = SEVERITY_ORDER.get((threshold or "low").lower(), 1)
    return sev >= thr


class Notifier:
    def __init__(self, config: dict, log_dir: Path):
        self.config = config.get("notifications", {})
        self.threshold = self.config.get("min_severity", "low")
        self.slack_url = self.config.get("slack_webhook")
        self.discord_url = self.config.get("discord_webhook")
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def notify_findings(self, findings: list) -> int:
        """
        Send notifications for a batch of findings.
        Returns count of notifications sent.
        """
        eligible = [
            f for f in findings
            if severity_meets_threshold(f["severity"], self.threshold)
        ]
        if not eligible:
            return 0

        # Always write to log file
        self._log_findings(eligible)

        # Slack
        if self.slack_url:
            self._send_slack(eligible)

        # Discord
        if self.discord_url:
            self._send_discord(eligible)

        return len(eligible)

    def _log_findings(self, findings: list):
        log_file = self.log_dir / "findings.log"
        with log_file.open("a") as f:
            for finding in findings:
                line = (
                    f"[{datetime.utcnow().isoformat()}] "
                    f"[{(finding['severity'] or 'info').upper()}] "
                    f"[{finding['program']} / {finding['platform']}] "
                    f"{finding['name']} @ {finding['target']}\n"
                )
                f.write(line)

    def _send_slack(self, findings: list):
        severity_emoji = {
            "critical": ":red_circle:",
            "high": ":orange_circle:",
            "medium": ":yellow_circle:",
            "low": ":white_circle:",
            "info": ":information_source:",
        }
        blocks = []
        for f in findings[:10]:  # Slack has block limits
            sev = (f["severity"] or "info").lower()
            emoji = severity_emoji.get(sev, ":white_circle:")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{f['name']}*\n"
                        f"Program: `{f['program']}` ({f['platform']})\n"
                        f"Target: `{f['target']}`\n"
                        f"Severity: *{sev.upper()}*"
                    ),
                },
            })
            blocks.append({"type": "divider"})

        payload = {
            "text": f":mag: {len(findings)} new finding(s) detected",
            "blocks": blocks,
        }
        try:
            r = requests.post(self.slack_url, json=payload, timeout=10)
            r.raise_for_status()
            logger.info(f"Slack notification sent for {len(findings)} findings")
        except Exception as e:
            logger.warning(f"Slack notification failed: {e}")

    def _send_discord(self, findings: list):
        severity_color = {
            "critical": 0xFF0000,
            "high": 0xFF6600,
            "medium": 0xFFCC00,
            "low": 0x00AAFF,
            "info": 0x888888,
        }
        embeds = []
        for f in findings[:10]:  # Discord embed limit
            sev = (f["severity"] or "info").lower()
            embeds.append({
                "title": f["name"],
                "color": severity_color.get(sev, 0x888888),
                "fields": [
                    {"name": "Program", "value": f"{f['program']} ({f['platform']})", "inline": True},
                    {"name": "Severity", "value": sev.upper(), "inline": True},
                    {"name": "Target", "value": f"`{f['target']}`", "inline": False},
                ],
                "footer": {"text": f"First seen: {f['first_seen']}"},
            })

        payload = {
            "content": f"**{len(findings)} new finding(s) detected**",
            "embeds": embeds,
        }
        try:
            r = requests.post(self.discord_url, json=payload, timeout=10)
            r.raise_for_status()
            logger.info(f"Discord notification sent for {len(findings)} findings")
        except Exception as e:
            logger.warning(f"Discord notification failed: {e}")
