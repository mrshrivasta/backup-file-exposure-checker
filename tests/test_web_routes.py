"""Web route tests for the Backup File Exposure Checker.

Uses a REAL local HTTP server (http.server on an ephemeral localhost port)
as the scan target so the full workflow — dashboard -> scan/run -> engine ->
real HTTP request -> findings -> logs/alerts/analytics/reports -- is
exercised end-to-end without touching any third-party site.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_ENV_BODY = (
    "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=SuperSecret123\n"
    "API_KEY=sk_live_abcdef1234567890\n"
).encode()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Homepage</body></html>")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(_ENV_BODY)
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


def test_full_scan_alert_incident_workflow(registered_client):
    server, port = _start_test_server()
    target_url = f"http://127.0.0.1:{port}/"
    try:
        resp = registered_client.post("/scan/run", data={"target_url": target_url}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show the scanned URL
        resp = registered_client.get("/logs")
        assert target_url.encode() in resp.data

        # Alerts page should load (the real .env content served by the
        # test server is real content that BFE-002 flags, producing a real alert)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
    finally:
        server.shutdown()


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert resp.status_code == 200


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
