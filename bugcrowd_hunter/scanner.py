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


def run_nuclei(targets_file: Path, output_file: Path,
               templates: list[str] = None, severity: list[str] = None,
               rate_limit: int = 25, timeout: int = 600) -> list[dict]:
    """Returns list of nuclei finding dicts."""
    if severity is None:
        severity = ["low", "medium", "high", "critical"]
    if templates is None:
        templates = ["cves", "exposures", "misconfiguration", "vulnerabilities"]
    # Resolve file paths to absolute so nuclei finds local templates reliably
    resolved_templates = []
    for t in templates:
        p = Path(t)
        if (t.endswith(".yaml") or "/" in t or "\\" in t) and p.exists():
            resolved_templates.append(str(p.resolve()))
        else:
            resolved_templates.append(t)  # category like "cves" or template id
    cmd = [
        "nuclei",
        "-l", str(targets_file),
        "-o", str(output_file),
        "-silent",
        "-rate-limit", str(rate_limit),
        "-bulk-size", "10",
        "-concurrency", "10",
        "-timeout", "10",
        "-severity", ",".join(severity),
        "-stats",
    ]
    for t in resolved_templates:
        cmd += ["-t", t]
    _run_cmd(cmd, timeout=timeout + 30, tool="nuclei")
    return _parse_jsonl(output_file)


def _run_cmd(cmd: list[str], timeout: int, tool: str, stdin_input: str = None):
    logger.debug(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin_input,
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
            raise ScanError(f"{tool} exited {result.returncode}:\n{err_msg}")
    except subprocess.TimeoutExpired:
        raise ScanError(f"{tool} timed out after {timeout}s")
    except FileNotFoundError:
        raise ScanError(f"{tool} not found in PATH")


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
                inp.write_text(target_name + "\n")
                severity = cfg.get("severity", ["low", "medium", "high", "critical"])
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
