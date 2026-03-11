# Bugcrowd Hunter v2

Automated recon and vulnerability scanning across **Bugcrowd and HackerOne** bug bounty programs.

## What's new in v2

- **HackerOne support** alongside Bugcrowd -- one tool for the whole ecosystem
- **Full recon pipeline**: `subfinder`/`amass` -> `dnsx` -> `httpx` -> `nuclei`, in stage order
- **Auto-pipeline**: discovered subdomains are automatically fed back into the queue for the next stage -- no manual wiring needed
- **Scope enforcement**: discovered subdomains are validated against program scope before being queued
- **Deduplicated findings** stored in SQLite with severity, first/last seen, and occurrence count
- **Slack and Discord notifications** when new findings come in above a configurable severity threshold
- **`report` command**: rich findings table across all programs with severity breakdown
- **`watch` command**: continuous sync + scan loop, runs forever and picks up new programs automatically
- **`program set` command**: per-program priority (1-10), exclusion, and notes
- **`gau` integration**: historical URL harvesting from Wayback Machine, CommonCrawl, and OTX
- **`amass` integration**: deeper passive subdomain enumeration
- **Results organized by platform**: `results/bugcrowd/<program>/` and `results/hackerone/<program>/`
- **`--force` re-queue**: rescan targets that have already been scanned

---

## Requirements

Python 3.11+ and the following tools via Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Make sure `~/go/bin` is in your `PATH`. Not all tools are required -- the tool will warn about missing ones and skip their scans.

---

## Installation

```bash
pip install -e .
```

Installs as both `bugcrowd-hunter` and `bch`.

---

## Quick start

```bash
bch tools                     # check what's installed

bch sync                      # sync Bugcrowd + HackerOne
bch sync --platform bugcrowd  # sync one platform
bch sync -p tesla             # sync a single program

bch list                      # list all programs
bch list --targets -p tesla   # list targets for a program
bch list --discovered -p tesla # list auto-discovered subdomains

bch queue                     # queue all scans
bch queue -p tesla -t nuclei  # queue only nuclei for tesla
bch queue -t nuclei --from-httpx -p tesla  # queue nuclei only for targets with httpx-confirmed responsive hosts
bch queue --force             # re-queue already-done scans

bch run                       # run pending scans
bch run -w 10                 # 10 parallel workers
bch run -t httpx              # only run httpx jobs
bch run -t nuclei -T http/technologies/tech-detect.yaml  # run nuclei with one template (path or id)
bch run -t nuclei -T ./templates/my-custom.yaml         # run local template across queued targets
# Nuclei templates are validated before each run; invalid templates cause the run to halt.

bch watch                     # continuous mode: sync + scan forever
bch watch --interval 7200     # re-sync every 2 hours

bch status                    # queue stats + finding counts
bch report                    # all findings, sorted by severity
bch report -p tesla           # findings for one program
bch report -s critical        # only critical findings
bch report --new-only         # unnotified findings only
bch report --json-out | jq .  # raw JSON

bch results -p tesla          # raw tool output
bch results -p tesla -t nuclei --json-out

bch program set tesla --priority 1   # make tesla highest priority
bch program set acme --exclude        # stop scanning acme
bch program set acme --include        # resume scanning acme
bch program set tesla --notes "Big scope, good payouts"

bch config                    # show config
bch config --edit             # open config in $EDITOR
```

---

## How the pipeline works

The tool runs in 4 stages per target, automatically chaining results:

```
Stage 1: subfinder / amass
  Input:  *.example.com (wildcard scope target)
  Output: api.example.com, staging.example.com, dev.example.com ...
  -> Discovered subdomains are saved as new targets and queued for stage 2+

Stage 2: dnsx / gau
  Input:  api.example.com (discovered subdomain)
  Output: Confirmed live DNS records / historical URLs

Stage 3: httpx
  Input:  api.example.com
  Output: Live HTTP endpoints with status codes, titles, tech stack

Stage 4: nuclei
  Input:  hostname (nuclei runs httpx internally, then runs templates)
  Output: Vulnerability findings (CVEs, misconfigs, tech detection, etc.)
```

You don't have to manage any of this manually. Run `bch queue` once for scope targets, and the rest fills in automatically as enumeration results come in.

---

## Notifications

Add your webhooks to `~/.bugcrowd-hunter/config.json`:

```json
"notifications": {
  "min_severity": "medium",
  "slack_webhook": "https://hooks.slack.com/services/...",
  "discord_webhook": "https://discord.com/api/webhooks/..."
}
```

Notifications fire automatically during `bch run` and `bch watch` whenever a new finding above the threshold is discovered. Findings are deduplicated, so you won't get repeat alerts for the same issue.

---

## Authentication

**Bugcrowd private programs:**
1. Log into bugcrowd.com
2. DevTools > Application > Cookies > copy `_bc_session`
3. Set `"bugcrowd_session"` in config, or `export BC_SESSION=...`

**HackerOne:**
1. Log into hackerone.com
2. DevTools > Application > Cookies > copy the auth token
3. Set `"hackerone_token"` in config, or `export H1_TOKEN=...`

---

## Config reference

```json
{
  "bugcrowd_session": "",
  "hackerone_token": "",
  "request_delay": 1.5,
  "workers": 5,
  "platforms": ["bugcrowd", "hackerone"],
  "notifications": {
    "min_severity": "low",
    "slack_webhook": "",
    "discord_webhook": ""
  },
  "tools": {
    "subfinder": { "rate_limit": 50, "timeout": 300 },
    "amass":     { "timeout": 600 },
    "dnsx":      { "rate_limit": 100, "timeout": 120, "resolver": "" },
    "httpx":     { "rate_limit": 50, "timeout": 300 },
    "gau":       { "timeout": 180 },
    "nuclei": {
      "rate_limit": 25,
      "timeout": 600,
      "templates": ["cves", "exposures", "misconfiguration", "vulnerabilities"]
    }
  },
  "tool_delays": {
    "subfinder": 1.0,
    "amass": 2.0,
    "dnsx": 0.5,
    "httpx": 0.5,
    "gau": 1.0,
    "nuclei": 2.0
  }
}
```

---

## Data layout

```
~/.bugcrowd-hunter/
  config.json
  state.db              # programs, targets, scan queue, findings
  logs/
  results/
    bugcrowd/
      <program>/
        subfinder/      # discovered subdomains
        amass/
        dnsx/           # DNS resolution results
        httpx/          # HTTP probe results
        gau/            # historical URLs
        nuclei/         # vulnerability findings (JSONL per target)
    hackerone/
      <program>/
        ...
```

---

- Only scan programs you are an authorized researcher on
- Read each program's policy before running automated tools
- Respect `rate_limit` settings, especially for nuclei
- Keep `request_delay` at 1.0+ to be polite to Bugcrowd/HackerOne APIs
- Some programs prohibit automated scanning -- `bch program set <code> --exclude` to skip them
- On VPN (e.g. Mullvad), set `tools.dnsx.resolver` to your VPN DNS (e.g. `"10.64.0.1"`) so dnsx can resolve.
