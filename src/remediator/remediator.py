#!/usr/bin/env python3
"""
BaghGuard Remediator

Opts-in users get automatic fix PRs for CRITICAL/HIGH dependency findings
that have a known fix_version and land in a plain requirements.txt pin.
Uses each user's own GitHub OAuth token (already stored from config-ui
sign-in, scope public_repo) to push a branch and open the PR directly on
their repo - no separate GitHub App or PAT needed.
"""

import base64
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('remediator')

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'baghguard')
DB_USER = os.getenv('DB_USER', 'baghguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '300'))
ALERT_SEVERITIES = os.getenv('ALERT_SEVERITIES', 'CRITICAL,HIGH').split(',')

# Matches a single requirements.txt pin line, e.g. "  flask==2.0.1  # comment"
_PIN_LINE_RE = re.compile(
    r'^(?P<indent>\s*)'
    r'(?P<name>[A-Za-z0-9][A-Za-z0-9_.\-]*(?:\[[A-Za-z0-9_,\-]+\])?)'
    r'(?P<op>\s*(?:==|>=|~=|<=)\s*)'
    r'(?P<version>[A-Za-z0-9_.\-]+)'
    r'(?P<rest>.*)$'
)


def get_db_connection():
    """Create database connection."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def get_remediate_users(conn) -> list:
    """Users who opted into auto-remediation, with their GitHub token."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT u.id, u.username, u.access_token
            FROM user_notify_settings n JOIN users u ON u.id = n.user_id
            WHERE n.remediate_enabled = true
        """)
        return cur.fetchall()


def get_candidate_findings(conn, user_id, severities: list) -> list:
    """Open, fixable, requirements.txt findings that haven't been attempted yet.

    The file_path regex is what scopes this to pip - npm/go findings have no
    requirements.txt target and never reach the remediator. The NOT EXISTS
    clause is what makes this idempotent: once a finding has any row in
    remediation_prs (open, failed, or unsupported), it's never retried.
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT f.id, f.repo, f.cve_id, f.package, f.file_path,
                   f.fix_version, f.severity, f.description, u.username
            FROM findings f
            JOIN users u ON u.id = f.owner_user_id
            WHERE f.owner_user_id = %s
              AND f.status = 'open'
              AND f.severity = ANY(%s)
              AND f.scanner IN ('trivy', 'grype')
              AND f.fix_version IS NOT NULL
              AND f.file_path ~* 'requirements\\.txt$'
              AND NOT EXISTS (
                SELECT 1 FROM remediation_prs r WHERE r.finding_id = f.id
              )
            ORDER BY
                CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END
        """, (user_id, severities))
        return cur.fetchall()


def record_remediation(conn, finding_id, status: str, pr_url: str = None,
                        branch_name: str = None, detail: str = None):
    """One row per finding, ever - this is the idempotency guard."""
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO remediation_prs (finding_id, status, pr_url, branch_name, detail)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (finding_id) DO NOTHING
        """, (finding_id, status, pr_url, branch_name, detail))
    conn.commit()


# --- GitHub API ---------------------------------------------------------

def github_api(method: str, path: str, token: str, payload: dict = None):
    """Minimal GitHub REST v3 client. Raises on any non-2xx response."""
    url = f"https://api.github.com{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    })
    with urllib.request.urlopen(req, timeout=15) as response:
        body = response.read()
        return json.loads(body) if body else {}


def get_default_branch(token: str, owner: str, repo: str, cache: dict) -> str:
    key = f"{owner}/{repo}"
    if key not in cache:
        info = github_api('GET', f"/repos/{owner}/{repo}", token)
        cache[key] = info['default_branch']
    return cache[key]


def get_file_contents(token: str, owner: str, repo: str, path: str, ref: str):
    info = github_api(
        'GET',
        f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}",
        token
    )
    content = base64.b64decode(info['content']).decode('utf-8')
    return content, info['sha']


def create_branch(token: str, owner: str, repo: str, branch: str, base_branch: str):
    ref_info = github_api(
        'GET', f"/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(base_branch)}", token
    )
    base_sha = ref_info['object']['sha']
    github_api('POST', f"/repos/{owner}/{repo}/git/refs", token, {
        'ref': f'refs/heads/{branch}',
        'sha': base_sha,
    })


def commit_file(token: str, owner: str, repo: str, path: str, branch: str,
                 content: str, sha: str, message: str):
    github_api('PUT', f"/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}", token, {
        'message': message,
        'content': base64.b64encode(content.encode('utf-8')).decode('ascii'),
        'sha': sha,
        'branch': branch,
    })


def open_pull_request(token: str, owner: str, repo: str, branch: str, base_branch: str,
                       title: str, body: str):
    pr = github_api('POST', f"/repos/{owner}/{repo}/pulls", token, {
        'title': title,
        'head': branch,
        'base': base_branch,
        'body': body,
    })
    return pr['html_url'], pr['number']


# --- requirements.txt patching ------------------------------------------

def _normalize_pkg_name(name: str) -> str:
    """PEP 503 normalization so 'Flask_Login' and 'flask-login' match."""
    return re.sub(r'[-_.]+', '-', name).lower()


def patch_requirements(content: str, pkg_name: str, installed_version: str,
                        fix_version: str):
    """Bump the one line pinning pkg_name==installed_version to fix_version.

    Returns the patched file content, or None if no line unambiguously pins
    this exact package at this exact version (transitive deps, range pins,
    or already-bumped lines are all left alone rather than guessed at).
    """
    target = _normalize_pkg_name(pkg_name)
    lines = content.splitlines(keepends=True)

    for i, line in enumerate(lines):
        stripped = line.rstrip('\n').rstrip('\r')
        match = _PIN_LINE_RE.match(stripped)
        if not match:
            continue
        if _normalize_pkg_name(match.group('name')) != target:
            continue
        if match.group('version') != installed_version:
            continue

        start, end = match.span('version')
        patched_line = stripped[:start] + fix_version + stripped[end:]
        newline = line[len(stripped):]  # preserves original \n / \r\n / none
        lines[i] = patched_line + newline
        return ''.join(lines)

    return None


def sanitize_branch_component(value: str) -> str:
    value = re.sub(r'[^A-Za-z0-9._-]+', '-', value or '').strip('-').lower()
    return value[:40] or 'x'


# --- Remediation flow -----------------------------------------------------

def remediate_finding(conn, finding: dict, token: str, repo_cache: dict):
    finding_id = finding['id']
    owner = finding['username']
    repo = finding['repo']
    file_path = finding['file_path']

    try:
        pkg_name, installed_version = finding['package'].rsplit(' ', 1)
    except ValueError:
        logger.warning(f"{owner}/{repo}: can't parse package/version from {finding['package']!r}")
        record_remediation(conn, finding_id, 'unsupported', detail='Unparseable package field')
        return

    try:
        default_branch = get_default_branch(token, owner, repo, repo_cache)
        content, sha = get_file_contents(token, owner, repo, file_path, default_branch)
    except Exception as e:
        logger.error(f"{owner}/{repo}: failed to fetch {file_path}: {e}")
        record_remediation(conn, finding_id, 'failed', detail=str(e))
        return

    patched = patch_requirements(content, pkg_name, installed_version, finding['fix_version'])
    if patched is None:
        logger.info(f"{owner}/{repo}: no line pins {pkg_name}=={installed_version} in {file_path}, skipping")
        record_remediation(
            conn, finding_id, 'unsupported',
            detail=f"No line pinning {pkg_name}=={installed_version} found in {file_path}"
        )
        return

    branch = (
        f"baghguard/fix-{sanitize_branch_component(pkg_name)}"
        f"-{sanitize_branch_component(finding['cve_id'] or 'nocve')}"
    )

    try:
        create_branch(token, owner, repo, branch, default_branch)
        commit_file(
            token, owner, repo, file_path, branch, patched, sha,
            message=f"Bump {pkg_name} to {finding['fix_version']} ({finding['cve_id'] or 'security fix'})",
        )
        pr_url, _ = open_pull_request(
            token, owner, repo, branch, default_branch,
            title=f"[BaghGuard] Fix {finding['severity']} {finding['cve_id'] or ''} in {pkg_name}".strip(),
            body=(
                f"BaghGuard detected a **{finding['severity']}** vulnerability in "
                f"`{pkg_name} {installed_version}` ({finding['cve_id'] or 'no CVE id'}) and opened this PR "
                f"automatically because you enabled auto-remediation.\n\n"
                f"**Fix:** bump to `{finding['fix_version']}`.\n\n"
                f"{finding['description'] or ''}\n\n"
                f"Please review the diff before merging."
            ),
        )
    except Exception as e:
        logger.error(f"{owner}/{repo}: failed to open remediation PR for {pkg_name}: {e}")
        record_remediation(conn, finding_id, 'failed', branch_name=branch, detail=str(e))
        return

    logger.info(f"{owner}/{repo}: opened {pr_url}")
    record_remediation(conn, finding_id, 'open', pr_url=pr_url, branch_name=branch)


def main():
    """Main loop - poll each opted-in user's fixable findings and open PRs."""
    logger.info("Starting BaghGuard Remediator")
    logger.info(f"Monitoring severities: {ALERT_SEVERITIES}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")

    # Wait for database
    for i in range(30):
        try:
            conn = get_db_connection()
            conn.close()
            logger.info("Database connection successful")
            break
        except Exception:
            logger.warning(f"Waiting for database... ({i+1}/30)")
            time.sleep(2)
    else:
        logger.error("Could not connect to database")
        sys.exit(1)

    while True:
        try:
            conn = get_db_connection()
            users = get_remediate_users(conn)

            for user in users:
                findings = get_candidate_findings(conn, user['id'], ALERT_SEVERITIES)
                if not findings:
                    continue

                logger.info(f"{user['username']}: {len(findings)} finding(s) eligible for auto-remediation")
                repo_cache = {}
                for finding in findings:
                    remediate_finding(conn, dict(finding), user['access_token'], repo_cache)

            conn.close()

        except Exception as e:
            logger.error(f"Error in remediation loop: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
