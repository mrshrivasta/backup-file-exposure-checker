"""
Security Engine — Backup File Exposure Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide to
establish the site's base origin, then makes a bounded set of additional
real, passive GET requests to a fixed list of well-known
backup/version-control/metadata file paths (.git/config, .env,
.svn/entries, database.sql, backup.zip, .DS_Store). A finding is only
produced when the response is BOTH a success status code AND its real
body content (text pattern or binary magic bytes) genuinely matches the
expected format for that file type — this avoids false positives from
generic soft-200 catch-all pages. Nothing is simulated: every finding is
based on an actual HTTP response.

SAFETY / SCOPE: Every request is a standard, read-only, non-destructive
GET — the same technique used by well-known passive/light scanners (OWASP
ZAP, Nikto) when probing for common exposed files. No exploit payloads
are ever sent, nothing is submitted, and the fixed probe list is short and
bounded (see BACKUP_PROBES) to keep the scan lightweight and
non-disruptive to the target.
"""
import re
import time
from urllib.parse import urlsplit, urlunsplit

import requests

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "BackupFileExposureChecker/1.0 (+https://github.com/mrshrivasta; educational security tool)"

_ENV_LINE_RE = re.compile(r"^[A-Z_][A-Z0-9_]*\s*=.+$", re.MULTILINE)
_SQL_DUMP_RE = re.compile(r"-- MySQL dump|CREATE TABLE|INSERT INTO|pg_dump", re.IGNORECASE)


def _check_git_config(resp):
    body = resp.text or ""
    return "[core]" in body and "repositoryformatversion" in body


def _check_env_file(resp):
    body = resp.text or ""
    if "<html" in body.lower() or not body.strip():
        return False
    return bool(_ENV_LINE_RE.search(body))


def _check_svn_entries(resp):
    body = resp.text or ""
    return "svn:" in body.lower() or body.strip().startswith(("10", "12", "<?xml"))


def _check_sql_dump(resp):
    body = resp.text or ""
    return bool(_SQL_DUMP_RE.search(body))


def _check_zip_archive(resp):
    content = resp.content or b""
    return content[:4] == b"PK\x03\x04"


def _check_ds_store(resp):
    content = resp.content or b""
    return content[:8] == b"\x00\x00\x00\x01Bud1"


# (path, rule_id, name, severity, checker)
BACKUP_PROBES = [
    ("/.git/config", "BFE-001", "Git Repository Config Exposed", "critical", _check_git_config),
    ("/.env", "BFE-002", "Environment File (.env) Exposed", "critical", _check_env_file),
    ("/.svn/entries", "BFE-003", "Subversion Metadata Exposed", "high", _check_svn_entries),
    ("/database.sql", "BFE-004", "Database Backup File Exposed", "critical", _check_sql_dump),
    ("/backup.sql", "BFE-004", "Database Backup File Exposed", "critical", _check_sql_dump),
    ("/backup.zip", "BFE-005", "Backup Archive File Exposed", "critical", _check_zip_archive),
    ("/.DS_Store", "BFE-006", "macOS .DS_Store Metadata File Exposed", "medium", _check_ds_store),
]


def _base_origin(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def _fetch(self):
        page_resp = self.session.get(
            self.target_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True,
        )
        origin = _base_origin(page_resp.url)

        probes = []
        for path, rule_id, name, severity, checker in BACKUP_PROBES:
            probe_url = origin + path
            try:
                r = self.session.get(probe_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)
                confirmed = r.status_code == 200 and checker(r)
                probes.append({
                    "url": probe_url, "rule_id": rule_id, "name": name, "severity": severity,
                    "status_code": r.status_code, "confirmed": confirmed,
                })
            except requests.exceptions.RequestException:
                self.errors_count += 1
                probes.append({
                    "url": probe_url, "rule_id": rule_id, "name": name, "severity": severity,
                    "status_code": None, "confirmed": False,
                })

        return {
            "url": page_resp.url,
            "status_code": page_resp.status_code,
            "headers": dict(page_resp.headers),
            "headers_lower": {k.lower(): v for k, v in page_resp.headers.items()},
            "origin": origin,
            "probes": probes,
            "elapsed_ms": round(page_resp.elapsed.total_seconds() * 1000, 1),
        }

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if not result:
                    continue
                result_list = result if isinstance(result, list) else [result]
                for item in result_list:
                    item["file_path"] = response["url"]
                    item["permissions_octal"] = str(response["status_code"])
                    item["owner_uid"] = None
                    item["owner_gid"] = None
                    findings.append(item)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "BFE-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["probes"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }
