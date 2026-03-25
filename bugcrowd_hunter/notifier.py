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
        self.scan_complete_cfg = self.config.get("scan_complete", {}) or {}
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

    def notify_scan_complete(self, event: dict) -> bool:
        """
        Notify when a scan completes (e.g. nuclei run finished).

        event keys (expected):
          - tool, target_name, program, platform
          - ok (bool), error (str|None)
          - results_count (int), duration_s (float), result_path (str|None)
        """
        tool = (event.get("tool") or "").strip().lower()
        enabled = bool(self.scan_complete_cfg.get("enabled", False))
        tools = [t.lower() for t in (self.scan_complete_cfg.get("tools") or ["nuclei"])]
        notify_on_error = bool(self.scan_complete_cfg.get("notify_on_error", True))

        ok = bool(event.get("ok", False))
        if not enabled:
            return False
        if tools and tool and tool not in tools:
            return False
        if (not ok) and not notify_on_error:
            return False

        # Always write to log file once enabled
        self._log_scan_complete(event)

        if self.slack_url:
            self._send_slack_scan_complete(event)
        if self.discord_url:
            self._send_discord_scan_complete(event)

        return True

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

    def _log_scan_complete(self, event: dict):
        log_file = self.log_dir / "scans.log"
        ok = bool(event.get("ok", False))
        status = "OK" if ok else "FAIL"
        duration_s = float(event.get("duration_s") or 0.0)
        results_count = int(event.get("results_count") or 0)
        result_path = event.get("result_path") or ""
        tool = event.get("tool") or "unknown"
        target_name = event.get("target_name") or "unknown"
        program = event.get("program") or "unknown"
        platform = event.get("platform") or "unknown"
        err = (event.get("error") or "").replace("\n", " ").strip()
        err_part = f" err={err}" if (not ok and err) else ""
        with log_file.open("a") as f:
            f.write(
                f"[{datetime.utcnow().isoformat()}] [{status}] "
                f"[{tool}] [{program} / {platform}] {target_name} "
                f"results={results_count} duration_s={duration_s:.2f} path={result_path}{err_part}\n"
            )

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

    def _send_slack_scan_complete(self, event: dict):
        ok = bool(event.get("ok", False))
        status_emoji = ":white_check_mark:" if ok else ":x:"
        tool = event.get("tool") or "unknown"
        target_name = event.get("target_name") or "unknown"
        program = event.get("program") or "unknown"
        platform = event.get("platform") or "unknown"
        duration_s = float(event.get("duration_s") or 0.0)
        results_count = int(event.get("results_count") or 0)
        result_path = event.get("result_path") or ""
        error = (event.get("error") or "").strip()

        lines = [
            f"{status_emoji} *{tool} scan complete*",
            f"Program: `{program}` ({platform})",
            f"Target: `{target_name}`",
            f"Duration: `{duration_s:.2f}s`",
            f"Results: `{results_count}`",
        ]
        if result_path:
            lines.append(f"Output: `{result_path}`")
        if (not ok) and error:
            trimmed = error if len(error) <= 500 else (error[:500] + "…")
            lines.append(f"*Error*: `{trimmed}`")

        payload = {"text": "\n".join(lines)}
        try:
            r = requests.post(self.slack_url, json=payload, timeout=10)
            r.raise_for_status()
            logger.info("Slack notification sent for scan completion")
        except Exception as e:
            logger.warning(f"Slack scan-complete notification failed: {e}")

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

    def _send_discord_scan_complete(self, event: dict):
        ok = bool(event.get("ok", False))
        color = 0x2ECC71 if ok else 0xE74C3C
        tool = event.get("tool") or "unknown"
        target_name = event.get("target_name") or "unknown"
        program = event.get("program") or "unknown"
        platform = event.get("platform") or "unknown"
        duration_s = float(event.get("duration_s") or 0.0)
        results_count = int(event.get("results_count") or 0)
        result_path = event.get("result_path") or ""
        error = (event.get("error") or "").strip()

        fields = [
            {"name": "Program", "value": f"{program} ({platform})", "inline": True},
            {"name": "Target", "value": f"`{target_name}`", "inline": False},
            {"name": "Duration", "value": f"`{duration_s:.2f}s`", "inline": True},
            {"name": "Results", "value": f"`{results_count}`", "inline": True},
        ]
        if result_path:
            fields.append({"name": "Output", "value": f"`{result_path}`", "inline": False})
        if (not ok) and error:
            trimmed = error if len(error) <= 900 else (error[:900] + "…")
            fields.append({"name": "Error", "value": f"`{trimmed}`", "inline": False})

        payload = {
            "content": f"**{tool} scan complete** ({'OK' if ok else 'FAILED'})",
            "embeds": [{
                "title": f"{tool} scan complete",
                "color": color,
                "fields": fields,
                "timestamp": datetime.utcnow().isoformat(),
            }],
        }
        try:
            r = requests.post(self.discord_url, json=payload, timeout=10)
            r.raise_for_status()
            logger.info("Discord notification sent for scan completion")
        except Exception as e:
            logger.warning(f"Discord scan-complete notification failed: {e}")
