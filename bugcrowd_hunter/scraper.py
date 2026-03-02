"""
Bugcrowd AND HackerOne scope scraper.

Enumerates:
  - All public Bugcrowd programs + in-scope domains/wildcards
  - All public HackerOne programs + in-scope domains/wildcards
"""

import re
import time
import logging
import requests
from typing import Generator
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Bugcrowd
BC_BASE = "https://bugcrowd.com"
BC_PROGRAMS_API = "https://bugcrowd.com/engagements.json"
BC_CHANGELOG_API = "https://bugcrowd.com/engagements/{program}/changelog.json"
BC_SCOPE_API = "https://bugcrowd.com/engagements/{program}/changelog/{changelog_id}.json"

# HackerOne
H1_BASE = "https://hackerone.com"
H1_GRAPHQL = "https://hackerone.com/graphql"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugBountyHunter/2.0; Security Research)",
    "Accept": "application/json",
}

WEB_CATEGORIES = {
    "website", "api", "url", "web_application", "other",
    "web", "api_endpoint", "wildcard",
}


@dataclass
class ScopeTarget:
    name: str
    category: str
    program: str
    platform: str = "bugcrowd"
    is_wildcard: bool = False
    in_scope: bool = False

    def __post_init__(self):
        self.is_wildcard = self.name.startswith("*.")

    @property
    def base_domain(self) -> str:
        return self.name.lstrip("*.").strip()


@dataclass
class Program:
    name: str
    code: str
    url: str
    platform: str = "bugcrowd"
    targets: list[ScopeTarget] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Bugcrowd
# ---------------------------------------------------------------------------

class BugcrowdScraper:
    def __init__(self, session_token: str = None, delay: float = 1.5):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if session_token:
            self.session.cookies.set("_bc_session", session_token, domain="bugcrowd.com")

    def _get(self, url: str, params: dict = None) -> dict | None:
        try:
            resp = self.session.get(url, params=params, timeout=15)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            logger.warning(f"[bugcrowd] HTTP {e.response.status_code} for {url}")
            return None
        except Exception as e:
            logger.error(f"[bugcrowd] Request failed for {url}: {e}")
            return None

    def iter_programs(self) -> Generator[Program, None, None]:
        page = 1
        seen = set()
        while True:
            data = self._get(BC_PROGRAMS_API, params={
                "page": page, "sort[]": "promoted", "hidden[]": "false"
            })
            if not data or not isinstance(data, dict):
                break 
            programs = data.get("engagements", [])
            if not programs:
                break
            for p in programs:
                code = p.get("briefUrl").split('/')[2]
                if not code or code in seen:
                    continue
                seen.add(code)
                yield Program(
                    name=p.get("name", code),
                    code=code,
                    url=f"{BC_BASE}/{code}",
                    platform="bugcrowd",
                )
            meta = data.get("meta", {})
            if not meta.get("has_more", True) or len(programs) == 0:
                break
            page += 1
            time.sleep(self.delay)

    def fetch_targets(self, program: Program) -> list[ScopeTarget]:
        targets = []
        latest_changelog = None
        # Hold up, we need to grab the changelog first to get the newest ID, and then
        #   we can use the changelog to find a list of targets
        changelog_url = BC_CHANGELOG_API.format(program=program.code)
        changelog_data = self._get(changelog_url)
        if not changelog_data or not isinstance(changelog_data, dict):
            return targets
        for changelog in changelog_data.get('changelogs', []):
            # Newest will have "changelogState": "Latest"
            if changelog.get("changelogState") == "Latest":
                latest_changelog = changelog.get("id")
                break

        url = BC_SCOPE_API.format(program=program.code, changelog_id=latest_changelog)
        data = self._get(url)
        if not data or not isinstance(data, dict):
            return targets
        # TODO: The scope is given on this page, but I need to check the JSON format
        # TODO: include out-of-scope stuff in the database for filtering
        for group in data.get("data", {}).get("scope", []):
            # in-scope targets have a field "inScope": "true"
            in_scope=group.get("inScope", False)
            for target in group.get("targets", []):
                category = target.get("category", "").lower()
                name = target.get("name", "").strip()
                if category not in WEB_CATEGORIES:
                    continue
                if not name or not _looks_like_domain(name):
                    continue
                targets.append(ScopeTarget(
                    name=name, category=category,
                    program=program.code, platform="bugcrowd",
                    in_scope=in_scope,
                ))
        time.sleep(self.delay)
        return targets


# ---------------------------------------------------------------------------
# HackerOne
# ---------------------------------------------------------------------------

H1_PROGRAMS_QUERY = """
query ($cursor: String) {
  opportunities(first: 100, after: $cursor, orderBy: {field: STARTED_AT, direction: DESC}) {
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      handle
      name
      url: canonicalUrl
      structuredScope(first: 100) {
        nodes {
          assetType
          assetIdentifier
          eligible_for_bounty: eligibleForBounty
          eligible_for_submission: eligibleForSubmission
        }
      }
    }
  }
}
"""


class HackerOneScraper:
    def __init__(self, session_token: str = None, delay: float = 1.5):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            **DEFAULT_HEADERS,
            "Content-Type": "application/json",
            "X-Auth-Token": session_token or "",
        })

    def _graphql(self, query: str, variables: dict = None) -> dict | None:
        try:
            resp = self.session.post(
                H1_GRAPHQL,
                json={"query": query, "variables": variables or {}},
                timeout=20,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"[hackerone] GraphQL request failed: {e}")
            return None

    def iter_programs(self) -> Generator[Program, None, None]:
        cursor = None
        seen = set()
        while True:
            data = self._graphql(H1_PROGRAMS_QUERY, {"cursor": cursor})
            if not data:
                break
            opps = data.get("data", {}).get("opportunities", {})
            nodes = opps.get("nodes", [])
            for node in nodes:
                handle = node.get("handle")
                if not handle or handle in seen:
                    continue
                seen.add(handle)
                program = Program(
                    name=node.get("name", handle),
                    code=handle,
                    url=node.get("url") or f"{H1_BASE}/{handle}",
                    platform="hackerone",
                )
                # Inline targets since they come with the program query
                program.targets = self._parse_h1_scope(node, handle)
                yield program
            page_info = opps.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(self.delay)

    def _parse_h1_scope(self, node: dict, handle: str) -> list[ScopeTarget]:
        targets = []
        scope_nodes = node.get("structuredScope", {}).get("nodes", [])
        for scope in scope_nodes:
            asset_type = scope.get("assetType", "").upper()
            identifier = (scope.get("assetIdentifier") or "").strip()
            if not scope.get("eligible_for_submission", True):
                continue
            # Only web asset types
            if asset_type not in ("URL", "WILDCARD", "DOMAIN", "API"):
                continue
            if not identifier or not _looks_like_domain(identifier):
                continue
            targets.append(ScopeTarget(
                name=identifier,
                category=asset_type.lower(),
                program=handle,
                platform="hackerone",
            ))
        return targets


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _looks_like_domain(value: str) -> bool:
    cleaned = value.lstrip("*.").strip()
    cleaned = re.sub(r"^https?://", "", cleaned).rstrip("/")
    cleaned = re.sub(r":\d+$", "", cleaned)
    # Remove path component
    cleaned = cleaned.split("/")[0]
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(domain_re.match(cleaned))
