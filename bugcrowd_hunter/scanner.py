"""
Scanner module.

Wraps external recon/scanning tools:
  - subfinder  : subdomain enumeration (wildcards)
  - httpx      : HTTP probing + fingerprinting
  - nuclei     : vulnerability scanning
  - dnsx       : DNS resolution
  - gau        : historical URL harvesting (wayback/commoncrawl/otx)
  - amass      : additional subdomain enumeration

Pipeline:
  subfinder/amass -> discovered subdomains -> fed back into targets table
                  -> dnsx resolves them -> live hosts
                  -> httpx probes them -> confirmed web endpoints
                  -> nuclei scans them -> findings
"""

import hashlib
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

TOOLS = {
    "subfinder": {
        "description": "Subdomain enumeration (passive)",
        "applies_to": "wildcard",
        "stage": 1,
    },
    "amass": {
        "description": "Subdomain enumeration (active + passive)",
        "applies_to": "wildcard",
        "stage": 1,
    },
    "dnsx": {
        "description": "DNS resolution -- filters live subdomains",
        "applies_to": "all",
        "stage": 2,
    },
    "httpx": {
        "description": "HTTP probing and tech fingerprinting",
        "applies_to": "all",
        "stage": 3,
    },
    "gau": {
        "description": "Historical URL harvesting",
        "applies_to": "all",
        "stage": 2,
    },
    "nuclei": {
        "description": "Vulnerability scanning",
        "applies_to": "all",
        "stage": 4,
    },
}

# Tools run in stage order: enumeration -> resolution -> probing -> vuln scan
STAGE_ORDER = [1, 2, 3, 4]


def check_tools() -> dict[str, bool]:
    return {tool: shutil.which(tool) is not None for tool in TOOLS}


def get_applicable_tools(is_wildcard: bool) -> list[str]:
    """Return tools for a target type, sorted by stage."""
    result = []
    for name, meta in TOOLS.items():
        if meta["applies_to"] == "all" or (meta["applies_to"] == "wildcard" and is_wildcard):
            result.append(name)
    result.sort(key=lambda t: TOOLS[t]["stage"])
    return result


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

class ScanError(Exception):
    pass


def run_subfinder(target: str, output_file: Path, rate_limit: int = 50,
                  timeout: int = 300) -> list[str]:
    """Returns list of discovered subdomains."""
    cmd = [
        "subfinder", "-d", target,
        "-o", str(output_file),
        "-json", "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", str(max(1, timeout // 60)),
    ]
    _run_cmd(cmd, timeout=timeout + 30, tool="subfinder")
    return _parse_subfinder_hosts(output_file)


def run_amass(target: str, output_file: Path, timeout: int = 600) -> list[str]:
    """Returns list of discovered subdomains."""
    cmd = [
        "amass", "enum",
        "-passive",
        "-d", target,
        "-json", str(output_file),
        "-timeout", str(timeout // 60),
    ]
    _run_cmd(cmd, timeout=timeout + 30, tool="amass")
    return _parse_amass_hosts(output_file)


def run_dnsx(domain: str, output_file: Path, rate_limit: int = 100,
             timeout: int = 120, resolver: str = None) -> list[str]:
    """Returns list of resolved (live) hostnames. Feeds domain via stdin. resolver=e.g. 10.64.0.1 for VPN."""
    cmd = [
        "dnsx",
        "-l", "-",
        "-o", str(output_file),
        "-json", "-silent",
        "-rate-limit", str(rate_limit),
        "-a", "-aaaa", "-cname", "-resp",
    ]
    if resolver and resolver.strip():
        # dnsx -r accepts one or comma-separated resolvers
        cmd.extend(["-r", resolver.strip()])
    _run_cmd(cmd, timeout=timeout + 30, tool="dnsx", stdin_input=domain.strip() + "\n")
    # dnsx JSON may use "host" or "hostname" depending on version
    rows = _parse_jsonl(output_file)
    return list({r.get("host") or r.get("hostname") or "" for r in rows if r.get("host") or r.get("hostname")})


def run_httpx(targets_file: Path, output_file: Path, rate_limit: int = 50,
              timeout: int = 300, resolver: str = None) -> list[dict]:
    """Returns list of live HTTP result dicts. Use -l so httpx reads targets from file."""
    cmd = [
        "httpx",
        "-l", str(targets_file),
        "-o", str(output_file),
        "-json", "-silent",
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-follow-redirects",
        "-title", "-status-code", "-tech-detect",
        "-content-length", "-web-server",
        "-favicon",
    ]
    if resolver and resolver.strip():
        cmd.extend(["-r", resolver.strip()])
    _run_cmd(cmd, timeout=timeout + 30, tool="httpx")
    return _parse_jsonl(output_file)


def run_gau(target: str, output_file: Path, timeout: int = 180) -> list[str]:
    """Returns list of historical URLs."""
    cmd = [
        "gau",
        "--providers", "wayback,commoncrawl,otx",
        "--o", str(output_file),
        target,
    ]
    _run_cmd(cmd, timeout=timeout + 30, tool="gau")
    urls = []
    if output_file.exists():
        urls = [l.strip() for l in output_file.read_text().splitlines() if l.strip()]
    return urls


# Error patterns Nuclei uses when validation fails (do not use -silent so we can parse these)
_NUCLEI_VALIDATE_ERROR_PATTERNS = [
    r"\[ERR\]",
    r"\[WRN\].*invalid",
    r"Error:",
    r"could not",
    r"failed to",
    r"invalid template",
]


def _resolve_nuclei_templates(templates: list[str]) -> list[str]:
    # Resolve file paths to absolute so nuclei finds local templates reliably.
    # Strip spurious .txt from template IDs (e.g. ssl/ssl-dns-names.txt -> ssl/ssl-dns-names).
    resolved_templates = []
    for t in templates:
        p = Path(t)
        if (t.endswith(".yaml") or "/" in t or "\\" in t) and p.exists():
            resolved_templates.append(str(p.resolve()))
        else:
            tid = t
            if tid.endswith(".txt") and "/" in tid and not Path(tid).exists():
                tid = tid[:-4]
            resolved_templates.append(tid)
    return resolved_templates


def validate_nuclei_templates(templates: list[str], timeout: int = 120) -> tuple[bool, list[str]]:
    """
    Run nuclei -validate (without -silent) and parse stdout+stderr for error lines.

    Returns (is_valid, list_of_error_lines). Caller should halt if not is_valid.
    """
    if shutil.which("nuclei") is None:
        return False, ["nuclei not found in PATH"]
    resolved = _resolve_nuclei_templates(templates)
    cmd = ["nuclei", "-validate"]
    for t in resolved:
        cmd += ["-t", t]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, ["nuclei template validation timed out"]
    output = (result.stdout or "") + (result.stderr or "")
    errors = []
    for line in output.splitlines():
        for pattern in _NUCLEI_VALIDATE_ERROR_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                errors.append(line.strip())
                break
    if not output.strip():
        errors.append("nuclei produced no output -- template may be unreadable")
    return (len(errors) == 0, errors)


def run_nuclei(targets_file: Path, output_file: Path,
               templates: list[str] = None, severity: list[str] = None,
               rate_limit: int = 25, timeout: int = 600) -> list[dict]:
    """Returns list of nuclei finding dicts. (severity is accepted for API compatibility but Nuclei has no -severity CLI flag.)"""
    if templates is None:
        templates = ["cves", "exposures", "misconfiguration", "vulnerabilities"]
    resolved_templates = _resolve_nuclei_templates(templates)
    output_path = output_file.resolve()
    # Use -u <target> for single-target runs so nuclei matches manual invocation
    # (e.g. nuclei -t ... -u hostname -j); -l <file> can behave differently.
    lines = targets_file.read_text().strip().splitlines()
    target_line = (lines[0].strip() if lines else "") or ""
    if not target_line:
        return []
    cmd = [
        "nuclei",
        "-duc",
        "-u", target_line,
        "-j",
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
    ]
    for t in resolved_templates:
        cmd += ["-t", t]
    # Capture from stdout: -j makes nuclei write one JSON object per line to stdout.
    result = _run_nuclei_cmd(cmd, timeout + 30)
    findings = _parse_jsonl_lines((result.stdout or "").strip())
    if findings:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(json.dumps(f) for f in findings) + "\n", encoding="utf-8")
    logger.info("nuclei output: from_stdout=%d", len(findings))
    return findings


def _run_nuclei_cmd(cmd: list[str], timeout: int):
    """Run nuclei, return subprocess result so caller can read stdout. Raises ScanError on failure."""
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode not in (0, 1):
            err_parts = []
            if result.stderr:
                err_parts.append(result.stderr.strip())
            if result.stdout and result.returncode != 0:
                err_parts.append(result.stdout.strip())
            err_msg = "\n".join(err_parts) if err_parts else "(no output)"
            if len(err_msg) > 1500:
                err_msg = err_msg[:1500] + "\n... (truncated)"
            raise ScanError(f"nuclei exited {result.returncode}:\n{err_msg}")
    except subprocess.TimeoutExpired:
        raise ScanError(f"nuclei timed out after {timeout}s")
    except FileNotFoundError:
        raise ScanError("nuclei not found in PATH")
    return result


def _parse_jsonl_lines(text: str) -> list[dict]:
    """Parse JSONL from a string (e.g. stdout); one JSON object per line."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def _run_cmd(
    cmd: list[str],
    timeout: int,
    tool: str,
    stdin_input: str = None,
    allowed_returncodes: tuple[int, ...] = (0, 1),
):
    logger.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_input,
        )
        if result.returncode not in allowed_returncodes:
            err_parts = []
            if result.stderr:
                err_parts.append(result.stderr.strip())
            if result.stdout and result.returncode != 0:
                err_parts.append(result.stdout.strip())
            err_msg = "\n".join(err_parts) if err_parts else "(no output)"
            if len(err_msg) > 1500:
                err_msg = err_msg[:1500] + "\n... (truncated)"
            raise ScanError(f"{tool} exited {result.returncode}:\n{err_msg}")
    except subprocess.TimeoutExpired:
        raise ScanError(f"{tool} timed out after {timeout}s")
    except FileNotFoundError:
        # Only when the executable is missing from PATH (e.g. nuclei not installed).
        # Missing/invalid template files cause the tool to exit non-zero, not this exception.
        raise ScanError(f"{tool} not found in PATH")


def _nuclei_input_line(target_name: str) -> str:
    """Target line for nuclei -l file. Pass through as-is so nuclei runs its internal
    httpx on hostnames (needed for tech-detect and similar templates); only strip."""
    return (target_name or "").strip()


def _parse_jsonl(path: Path) -> list[dict]:
    if not path or not path.exists():
        return []
    results = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def _parse_jsonl_field(path: Path, field: str) -> list[str]:
    return [r[field] for r in _parse_jsonl(path) if field in r]


def _parse_subfinder_hosts(path: Path) -> list[str]:
    hosts = []
    for item in _parse_jsonl(path):
        h = item.get("host") or item.get("subdomain")
        if h:
            hosts.append(h.strip())
    return list(set(hosts))


def _parse_amass_hosts(path: Path) -> list[str]:
    hosts = []
    for item in _parse_jsonl(path):
        h = item.get("name")
        if h:
            hosts.append(h.strip())
    return list(set(hosts))


# ---------------------------------------------------------------------------
# Finding fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_nuclei(finding: dict, program: str) -> str:
    """Create a stable dedup fingerprint for a nuclei finding."""
    template_id = finding.get("template-id", "")
    host = finding.get("host", "")
    matched = finding.get("matched-at", "")
    key = f"{program}|{template_id}|{host}|{matched}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def fingerprint_httpx(finding: dict, program: str) -> str:
    """Fingerprint for interesting httpx results (e.g. unusual status codes)."""
    url = finding.get("url", "")
    status = finding.get("status-code", "")
    key = f"{program}|httpx|{url}|{status}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, results_dir: Path, config: dict = None):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}

    def result_path(self, program: str, tool: str, target_name: str,
                    platform: str = "bugcrowd") -> Path:
        safe_name = target_name.replace("*", "WILDCARD").replace("/", "_").replace(":", "_")
        d = self.results_dir / platform / program / tool
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe_name}.jsonl"

    def input_path(self, program: str, tool: str, target_name: str,
                   platform: str = "bugcrowd") -> Path:
        safe_name = target_name.replace("*", "WILDCARD").replace("/", "_").replace(":", "_")
        d = self.results_dir / platform / program / tool
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe_name}.input.txt"

    def run_tool(self, tool: str, target_name: str, base_domain: str,
                 is_wildcard: bool, program: str,
                 platform: str = "bugcrowd",
                 nuclei_template: str = None) -> tuple[Optional[Path], Optional[str], list]:
        """
        Run tool against a target.
        Returns (result_file, error, extra_data).
        extra_data = list of discovered subdomains for enumeration tools,
                     list of finding dicts for nuclei/httpx.
        """
        out = self.result_path(program, tool, target_name, platform)
        inp = self.input_path(program, tool, target_name, platform)
        cfg = self.config.get(tool, {})
        rate_limit = cfg.get("rate_limit", 50)
        timeout = cfg.get("timeout", 300)
        extra = []

        try:
            if tool == "subfinder":
                extra = run_subfinder(base_domain, out, rate_limit=rate_limit, timeout=timeout)

            elif tool == "amass":
                extra = run_amass(base_domain, out, timeout=cfg.get("timeout", 600))

            elif tool == "dnsx":
                resolver = cfg.get("resolver") or None
                extra = run_dnsx(
                    base_domain, out,
                    rate_limit=rate_limit, timeout=timeout,
                    resolver=resolver,
                )

            elif tool == "httpx":
                inp.write_text(target_name + "\n")
                resolver = cfg.get("resolver") or None
                extra = run_httpx(
                    inp, out,
                    rate_limit=rate_limit, timeout=timeout,
                    resolver=resolver,
                )
                inp.unlink(missing_ok=True)

            elif tool == "gau":
                extra = run_gau(base_domain, out, timeout=cfg.get("timeout", 180))

            elif tool == "nuclei":
                inp.write_text(_nuclei_input_line(target_name) + "\n")
                severity = cfg.get("severity", ["info", "low", "medium", "high", "critical"])
                templates = (
                    [nuclei_template] if nuclei_template
                    else cfg.get("templates", ["cves", "exposures", "misconfiguration", "vulnerabilities"])
                )
                extra = run_nuclei(inp, out, templates=templates, severity=severity,
                                   rate_limit=rate_limit, timeout=timeout)
                inp.unlink(missing_ok=True)

            else:
                return None, f"Unknown tool: {tool}", []

            return out, None, extra

        except ScanError as e:
            return None, str(e), []
        except Exception as e:
            return None, f"Unexpected error: {e}", []

    def parse_results(self, result_file: Path) -> list[dict]:
        return _parse_jsonl(result_file)
