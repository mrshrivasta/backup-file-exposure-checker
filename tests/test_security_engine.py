"""Tests for the Backup File Exposure Checker's Security Engine and rules.

Rule-level tests use synthetic response dicts with pre-built 'probes'
lists (no network calls). The engine-level tests spin up a REAL local
HTTP server (Python's http.server, on an ephemeral localhost port) that
genuinely serves realistic content at a couple of the probed backup
paths, and perform REAL HTTP requests against it via the actual
ScanEngine code path — genuine end-to-end testing without touching any
third-party site. Every request made is a standard, passive, read-only
GET.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_git_config_exposed,
    rule_env_file_exposed,
    rule_svn_metadata_exposed,
    rule_database_backup_exposed,
    rule_backup_archive_exposed,
    rule_ds_store_exposed,
)


def resp(url="https://example.com/", probes=None):
    return {"url": url, "status_code": 200, "probes": probes or []}


def probe(rule_id="BFE-001", name="Git Repository Config Exposed", severity="critical",
          url="https://example.com/.git/config", status_code=200, confirmed=True):
    return {
        "url": url, "rule_id": rule_id, "name": name, "severity": severity,
        "status_code": status_code, "confirmed": confirmed,
    }


def test_confirmed_git_config_flagged():
    result = rule_git_config_exposed(resp(probes=[probe(rule_id="BFE-001", confirmed=True)]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-001"


def test_unconfirmed_probe_not_flagged():
    result = rule_git_config_exposed(resp(probes=[probe(rule_id="BFE-001", confirmed=False)]))
    assert result == []


def test_env_file_confirmed_flagged():
    result = rule_env_file_exposed(resp(probes=[probe(rule_id="BFE-002", name="Environment File (.env) Exposed", severity="critical")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-002"


def test_svn_confirmed_flagged():
    result = rule_svn_metadata_exposed(resp(probes=[probe(rule_id="BFE-003", name="Subversion Metadata Exposed", severity="high")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-003"


def test_database_backup_confirmed_flagged():
    result = rule_database_backup_exposed(resp(probes=[probe(rule_id="BFE-004", name="Database Backup File Exposed", severity="critical")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-004"


def test_backup_archive_confirmed_flagged():
    result = rule_backup_archive_exposed(resp(probes=[probe(rule_id="BFE-005", name="Backup Archive File Exposed", severity="critical")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-005"


def test_ds_store_confirmed_flagged():
    result = rule_ds_store_exposed(resp(probes=[probe(rule_id="BFE-006", name="macOS .DS_Store Metadata File Exposed", severity="medium")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "BFE-006"


def test_wrong_rule_id_not_matched():
    result = rule_ds_store_exposed(resp(probes=[probe(rule_id="BFE-004")]))
    assert result == []


_GIT_CONFIG_BODY = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    "[remote \"origin\"]\n\turl = https://example.com/app.git\n"
).encode()

_ENV_BODY = (
    "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=SuperSecret123\n"
    "API_KEY=sk_live_abcdef1234567890\n"
).encode()

_DS_STORE_BODY = b"\x00\x00\x00\x01Bud1" + b"\x00" * 32


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Homepage</body></html>")
        elif self.path == "/.git/config":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(_GIT_CONFIG_BODY)
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(_ENV_BODY)
        elif self.path == "/.DS_Store":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(_DS_STORE_BODY)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real bounded probing of a local
    server we control (not a third party). Every request is a standard,
    passive, read-only GET."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        assert len(result["response"]["probes"]) >= 6
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "BFE-001" in rule_ids  # real .git/config content confirmed
        assert "BFE-002" in rule_ids  # real .env content confirmed
        assert "BFE-006" in rule_ids  # real .DS_Store magic bytes confirmed
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "BFE-000" for f in result["findings"])
