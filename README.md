# Backup File Exposure Checker

A real, no-mock-data security auditing tool that makes a **bounded set of real, passive HTTP GET requests** to well-known backup/version-control/metadata file paths on a URL you authorize — `.git/config`, `.env`, `.svn/entries`, `database.sql`/`backup.sql`, `backup.zip`, and `.DS_Store` — and only reports an exposure when the real response **both succeeds AND its real content (text pattern or binary magic bytes) genuinely matches the expected format** for that file type, avoiding false positives from generic soft-200 catch-all pages.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from actual responses received from the target server at scan time.

- **Bounded, passive, read-only by design.** This tool checks a short, fixed list of well-known backup/version-control/metadata file paths (see the Detection Rules table). Every request is a standard, non-destructive `GET` — the same technique used by well-known passive/light scanners (OWASP ZAP, Nikto) when probing for common exposed files. No exploit payloads are ever sent, and nothing is submitted, modified, or downloaded beyond the confirming GET request itself.
- **Signature-confirmed to avoid false positives.** A finding is only produced when the response is BOTH a success status AND its real body/bytes contain a specific, genuine content signature unique to that file type (e.g. `[core]`/`repositoryformatversion` for `.git/config`, `KEY=VALUE`-style lines for `.env`, SQL dump markers for database backups, `PK\x03\x04` magic bytes for zip archives, and the `Bud1` signature for `.DS_Store`) — not merely "a 200 status at this path," which many single-page apps or catch-all routers would produce regardless.
- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a set of harmless-looking GET requests for common file paths.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit, or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and DevOps engineers verifying their production deployment doesn't accidentally ship a `.git` directory, a `.env` file, or a leftover SQL dump.
- AppSec engineers doing a fast, safe first pass for backup-file exposure ahead of a deeper authorized assessment.
- SRE teams auditing infrastructure and deployment pipelines for leftover version-control metadata or database backups accidentally left web-accessible.
- Students and educators studying real-world backup-file information-disclosure risk with a genuine, working, bounded, non-destructive tool.

## Why use this project

An exposed `.git` directory or `.env` file is one of the single most consequential, and most common, deployment mistakes on the web: an exposed `.git/config` can be leveraged with tools like `git-dumper` to reconstruct an application's entire source tree — including every secret ever committed — while an exposed `.env` file hands an attacker plaintext database credentials, API keys, and signing secrets directly. Database dumps, backup archives, and `.DS_Store` files carry similarly severe, and similarly common, real-world impact. Automated bots scan the internet for exactly these paths continuously. This tool automates a real, bounded, signature-confirmed check for exactly this exposure class, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility.

---

## Detection Rules

Every rule below is evaluated against the **actual results of real, passive HTTP GET requests** made to a fixed, bounded list of backup/version-control/metadata paths during a scan.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| BFE-001 | Git Repository Config Exposed | **Critical** | A real `.git/config` file is confirmed publicly accessible, enabling full source-tree reconstruction. |
| BFE-002 | Environment File (.env) Exposed | **Critical** | A real `.env` file is confirmed publicly accessible, typically leaking credentials and API keys directly. |
| BFE-003 | Subversion Metadata Exposed | High | A real `.svn/entries` metadata file is confirmed publicly accessible. |
| BFE-004 | Database Backup File Exposed | **Critical** | A real SQL database dump (`database.sql` / `backup.sql`) is confirmed publicly accessible. |
| BFE-005 | Backup Archive File Exposed | **Critical** | A real backup archive (`backup.zip`) is confirmed publicly accessible, identified by genuine ZIP magic bytes. |
| BFE-006 | macOS .DS_Store Metadata File Exposed | Medium | A real `.DS_Store` file is confirmed publicly accessible, identified by genuine `.DS_Store` magic bytes. |
| BFE-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a backup-file finding — an operational note. |

---

## Architecture

```
backup-file-exposure-checker/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — real, bounded, signature-confirmed file probing
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating real confirmed probes
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd backup-file-exposure-checker
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic probe-result dicts, and a genuine end-to-end test that boots a real local HTTP server on an ephemeral `127.0.0.1` port that genuinely serves realistic `.git/config`-style, `.env`-style, and `.DS_Store`-style content at a few of the probed paths, then performs real, passive HTTP requests against it via the real Security Engine — no third-party network calls are made during testing.

---

## Frequently Asked Questions

**What does the Backup File Exposure Checker check?**
It makes a bounded set of real, passive GET requests to well-known backup/version-control/metadata paths on a URL you authorize (`.git/config`, `.env`, `.svn/entries`, `database.sql`/`backup.sql`, `backup.zip`, `.DS_Store`), and only reports an exposure when the real response is both a success status AND its real body/bytes contain a genuine content signature for that specific file type — never sample data, and no exploit payload is ever sent.

**Who should use the Backup File Exposure Checker?**
Web developers and security engineers auditing whether backup, version-control, or database files are accidentally left publicly accessible in production, on sites and applications they own or are explicitly authorized to test.

**Why require a content signature match instead of just checking for a 200 status?**
Many modern applications and single-page-app routers return 200 for almost any path (serving a generic app shell). Requiring the response body or bytes to contain a genuine, specific signature for the actual file type avoids false-positive findings from those setups.

**Does this tool download or exfiltrate the exposed files?**
No. It only inspects enough of the real response body/bytes needed to confirm the content signature for each file type. It does not save, exfiltrate, or further process any exposed file contents beyond that confirmation.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
