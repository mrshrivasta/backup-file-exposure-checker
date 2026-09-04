"""
Detection Rules — Backup File Exposure Checker
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects the REAL results of a bounded set of passive GET
probes made against well-known backup/version-control/metadata file
paths (see app/security_engine.BACKUP_PROBES). A probe is only
"confirmed" when BOTH the real HTTP status was 200 AND the real
response body/bytes genuinely matched a specific, known signature for
that file type — this avoids false positives from generic soft-200
catch-all pages. No sample data is generated, and no exploit payload is
ever sent.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _confirmed_probes_for(response, rule_id):
    return [p for p in (response.get("probes") or []) if p["rule_id"] == rule_id and p["confirmed"]]


def _make_finding(response, probe):
    return {
        "rule_id": probe["rule_id"],
        "rule_name": probe["name"],
        "severity": probe["severity"],
        "description": (
            f"{probe['name']} was confirmed at {probe['url']} — HTTP "
            f"{probe['status_code']} with real content matching the "
            f"expected signature for this file type."
        ),
    }


def rule_git_config_exposed(response):
    """BFE-001: A real .git/config file is publicly exposed. This is one
    of the most dangerous and common misconfigurations: an exposed .git
    directory can be leveraged (via tools like git-dumper) to
    reconstruct the entire application source tree, including any
    hardcoded secrets, API keys, or internal logic ever committed."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-001")]


def rule_env_file_exposed(response):
    """BFE-002: A real .env environment file is publicly exposed. These
    files routinely contain database credentials, API keys, secret
    signing keys, and third-party service tokens in plaintext — direct,
    immediate compromise if reached by an attacker."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-002")]


def rule_svn_metadata_exposed(response):
    """BFE-003: A real Subversion (.svn/entries) metadata file is
    publicly exposed. Similar to an exposed .git directory, this can
    allow an attacker to reconstruct source files and revision history
    from the working-copy metadata."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-003")]


def rule_database_backup_exposed(response):
    """BFE-004: A real SQL database backup/dump file is publicly
    exposed. Database dumps typically contain complete table contents,
    including user records, password hashes, and other sensitive
    business or personal data."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-004")]


def rule_backup_archive_exposed(response):
    """BFE-005: A real backup archive (zip) file is publicly exposed.
    Backup archives frequently contain full application source code,
    configuration files with embedded secrets, and other sensitive
    assets never intended for public access."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-005")]


def rule_ds_store_exposed(response):
    """BFE-006: A real macOS .DS_Store metadata file is publicly
    exposed. .DS_Store files can leak a listing of file and folder
    names in a directory that may not otherwise be discoverable,
    aiding an attacker's reconnaissance."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "BFE-006")]


ALL_RULES = [
    rule_git_config_exposed,
    rule_env_file_exposed,
    rule_svn_metadata_exposed,
    rule_database_backup_exposed,
    rule_backup_archive_exposed,
    rule_ds_store_exposed,
]
