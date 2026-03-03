"""
Worker system for managing concurrent scans.

Key improvements over v1:
  - Discovered subdomains (from subfinder/amass) are automatically fed back
    into the targets table and queued for the next stage (dnsx -> httpx -> nuclei)
  - Findings from nuclei/httpx are deduplicated and stored in the findings table
  - Scope enforcement: checks discovered subdomains against program scope before queuing
  - Per-tool rate limiting with global locks (thread-safe lock creation)
  - Notification callbacks on new findings
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from .state import StateManager
from .scanner import Scanner, get_applicable_tools, fingerprint_nuclei, fingerprint_httpx
from .notifier import Notifier

logger = logging.getLogger(__name__)

# Tools that produce subdomains to feed back into the pipeline
ENUMERATION_TOOLS = {"subfinder", "amass"}

# Tools that produce structured findings to store
FINDING_TOOLS = {"nuclei"}

# httpx status codes worth recording as findings
INTERESTING_HTTPX_STATUSES = {401, 403, 500, 503}


class WorkerPool:
    def __init__(
        self,
        state: StateManager,
        scanner: Scanner,
        notifier: Notifier,
        workers: int = 5,
        tool_delays: dict = None,
        on_complete: Callable = None,
        nuclei_template: str = None,
        tool_filter: str = None,
    ):
        self.state = state
        self.scanner = scanner
        self.notifier = notifier
        self.workers = workers
        self.tool_delays = tool_delays or {}
        self.on_complete = on_complete
        self.nuclei_template = nuclei_template
        self.tool_filter = tool_filter
        self._stop = threading.Event()
        # Guards mutation of _tool_locks dict itself (thread-safe lazy creation)
        self._tool_locks_lock = threading.Lock()
        self._tool_locks: dict[str, threading.Lock] = {}
        self._tool_last_run: dict[str, float] = {}
        self._findings_lock = threading.Lock()

    def _get_tool_lock(self, tool: str) -> threading.Lock:
        with self._tool_locks_lock:
            if tool not in self._tool_locks:
                self._tool_locks[tool] = threading.Lock()
            return self._tool_locks[tool]

    def _rate_limit_tool(self, tool: str):
        """Enforce per-tool minimum delay between consecutive jobs."""
        lock = self._get_tool_lock(tool)
        with lock:
            delay = self.tool_delays.get(tool, 0.5)
            last = self._tool_last_run.get(tool, 0)
            elapsed = time.time() - last
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self._tool_last_run[tool] = time.time()

    def _process_scan(self, scan_row) -> tuple:
        scan_id = scan_row["id"]
        tool = scan_row["tool"]
        target_name = scan_row["target_name"]
        base_domain = scan_row["base_domain"]
        is_wildcard = bool(scan_row["is_wildcard"])
        program = scan_row["program"]
        platform = scan_row["platform"]
        target_id = scan_row["target_id"]

        # Atomically claim -- prevents two workers from running the same scan
        if not self.state.claim_scan(scan_id):
            return scan_id, None, "Already claimed"

        self._rate_limit_tool(tool)
        logger.info(f"[{tool}] {target_name} ({program}/{platform})")

        result_file, error, extra = self.scanner.run_tool(
            tool=tool,
            target_name=target_name,
            base_domain=base_domain,
            is_wildcard=is_wildcard,
            program=program,
            platform=platform,
            nuclei_template=self.nuclei_template,
        )

        result_path = (
            str(result_file.relative_to(self.scanner.results_dir))
            if result_file else None
        )
        self.state.complete_scan(scan_id, result_file=result_path, error=error)

        if error:
            logger.warning(f"[{tool}] {target_name} FAILED: {error}")
        else:
            logger.info(f"[{tool}] {target_name} -> {len(extra)} results")

            if tool in ENUMERATION_TOOLS and extra:
                self._ingest_discovered_subdomains(
                    subdomains=extra,
                    program=program,
                    platform=platform,
                    parent_target_id=target_id,
                    parent_base_domain=base_domain,
                )

            if tool in FINDING_TOOLS and extra:
                self._ingest_findings(extra, program, platform, target_name, tool)

            if tool == "httpx" and extra:
                self._ingest_httpx_findings(extra, program, platform)

        if self.on_complete:
            self.on_complete(scan_id, target_name, tool, result_file, error)

        return scan_id, result_file, error

    def _ingest_discovered_subdomains(self, subdomains: list[str], program: str,
                                      platform: str, parent_target_id: int,
                                      parent_base_domain: str):
        """
        Add newly discovered subdomains to the targets table and queue follow-up scans.
        Enforces scope: only accepts subdomains of the parent base domain.
        Skips enumeration tools to prevent infinite loops.
        """
        queued = 0
        ingested = 0
        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            if not subdomain:
                continue
            # Scope check
            if not (subdomain == parent_base_domain or
                    subdomain.endswith("." + parent_base_domain)):
                logger.debug(f"Out of scope, skipping: {subdomain}")
                continue
            # Check if the subdomain is excluded from the program
            out_of_scope_names = self.state.get_out_of_scope_target_names(program, platform)
            if subdomain in out_of_scope_names:
                logger.debug(f"Out of scope, skipping: {subdomain}")
                continue

            tid = self.state.upsert_target(
                program=program,
                platform=platform,
                name=subdomain,
                base_domain=subdomain,
                is_wildcard=False,
                category="discovered",
                source="discovered",
                discovered_from=parent_target_id,
                in_scope=True,
            )
            if tid is None:
                continue
            ingested += 1

            # Queue next-stage tools only (no enumeration -- avoids loops)
            next_tools = [t for t in get_applicable_tools(False)
                          if t not in ENUMERATION_TOOLS]
            for next_tool in next_tools:
                self.state.queue_scan(tid, next_tool)
                queued += 1

        if ingested:
            logger.info(f"Ingested {ingested} subdomains, queued {queued} follow-up scans")

    def _ingest_findings(self, findings: list[dict], program: str, platform: str,
                         target: str, tool: str):
        """Store nuclei findings and trigger notifications for new ones."""
        any_new = False
        for finding in findings:
            name = (finding.get("info", {}).get("name")
                    or finding.get("template-id", "unknown"))
            severity = finding.get("info", {}).get("severity", "info").lower()
            fp = fingerprint_nuclei(finding, program)

            _fid, is_new = self.state.upsert_finding(
                program=program, platform=platform,
                target=target, tool=tool,
                name=name, severity=severity,
                fingerprint=fp, raw=finding,
            )
            if is_new:
                any_new = True

        if any_new:
            self._fire_notifications()

    def _ingest_httpx_findings(self, results: list[dict], program: str, platform: str):
        """Store interesting httpx status codes as info-level findings."""
        any_new = False
        for r in results:
            status = r.get("status-code")
            if status in INTERESTING_HTTPX_STATUSES:
                fp = fingerprint_httpx(r, program)
                name = f"HTTP {status} response"
                _fid, is_new = self.state.upsert_finding(
                    program=program, platform=platform,
                    target=r.get("url", ""),
                    tool="httpx",
                    name=name,
                    severity="info",
                    fingerprint=fp,
                    raw=r,
                )
                if is_new:
                    any_new = True

        if any_new:
            self._fire_notifications()

    def _fire_notifications(self):
        """Send notifications for all unnotified findings (thread-safe)."""
        with self._findings_lock:
            unnotified = self.state.get_unnotified_findings()
            if not unnotified:
                return
            sent = self.notifier.notify_findings([dict(f) for f in unnotified])
            if sent:
                self.state.mark_findings_notified([f["id"] for f in unnotified])

    def run(self, max_jobs: int = None, batch_size: int = 20, poll_interval: float = 5.0):
        """
        Pull pending scans from the DB queue and process them with the thread pool.
        Runs until the queue is empty or max_jobs is reached.
        Ctrl+C safe -- shuts down gracefully.
        """
        logger.info(f"Starting worker pool: {self.workers} workers")
        jobs_done = 0
        self.state.reset_stale_scans()

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = set()
            try:
                while not self._stop.is_set():
                    # Collect completed futures and surface any exceptions
                    done = {f for f in futures if f.done()}
                    futures -= done
                    for f in done:
                        try:
                            f.result()
                        except Exception as e:
                            logger.error(f"Worker exception: {e}")

                    if max_jobs and jobs_done >= max_jobs:
                        break

                    slots = self.workers - len(futures)
                    if slots <= 0:
                        time.sleep(0.5)
                        continue

                    pending = self.state.get_pending_scans(
                        tool=self.tool_filter, limit=min(slots, batch_size)
                    )

                    if not pending:
                        if not futures:
                            # Queue might be getting populated by ingest callbacks --
                            # wait one poll cycle before declaring done
                            time.sleep(poll_interval)
                            if not self.state.get_pending_scans(
                                tool=self.tool_filter, limit=1
                            ):
                                logger.info("Queue fully drained. Stopping.")
                                break
                        else:
                            time.sleep(0.5)
                        continue

                    for scan_row in pending:
                        future = pool.submit(self._process_scan, scan_row)
                        futures.add(future)
                        jobs_done += 1

            except KeyboardInterrupt:
                logger.info("Interrupted -- shutting down workers gracefully")
                self._stop.set()

        logger.info(f"Worker pool finished. Jobs processed: {jobs_done}")

    def stop(self):
        self._stop.set()


def populate_scan_queue(state: StateManager, tools: list[str] = None,
                        program: str = None, platform: str = None,
                        force: bool = False, from_httpx: bool = False) -> int:
    """
    Populate the scan queue.
    By default uses scope targets. With from_httpx=True, uses targets that have
    a completed httpx scan (confirmed web sites) and queues the requested tools
    (e.g. nuclei) for them.
    Returns number of jobs queued.
    """
    if from_httpx:
        targets = state.get_targets_with_scan_done("httpx", program=program, platform=platform)
        source_desc = "targets with httpx done"
    else:
        targets = state.get_targets(program=program, platform=platform, source="scope", in_scope=True)
        source_desc = "scope targets"
    queued = 0
    for t in targets:
        is_wildcard = bool(t["is_wildcard"])
        applicable = get_applicable_tools(is_wildcard)
        if tools:
            applicable = [x for x in applicable if x in tools]
        for tool in applicable:
            _sid, inserted = state.queue_scan(t["id"], tool, force=force)
            if inserted:
                queued += 1
    logger.info(f"Queued {queued} scan jobs for {len(targets)} {source_desc}")
    return queued
