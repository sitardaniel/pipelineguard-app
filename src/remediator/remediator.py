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
from packaging.version import Version, InvalidVersion

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


def group_candidates(findings: list) -> list:
    """Group findings that are really the same pin (repo + file + package),
    just flagged by multiple CVEs. Opening one competing PR per CVE means
    merging any one of them leaves the others stale/conflicting against a
    version pin that's no longer there - grouping means one PR per pin,
    covering every CVE it happens to also fix."""
    groups = {}
    for f in findings:
        key = (f['repo'], f['file_path'], f['package'])
        groups.setdefault(key, []).append(f)
    return list(groups.values())


def _parsed_version(version_str: str):
    try:
        return Version(version_str)
    except InvalidVersion:
        return None


def pick_best_fix(group: list) -> dict:
    """The group member whose fix_version is highest wins - its fix_version
    is the one actually applied, since it's guaranteed to also clear every
    lower-versioned CVE in the same group. Falls back to string comparison
    only if a fix_version isn't valid PEP 440 (rare scanner-output oddity),
    rather than guessing wrong."""
    parsed = [(f, _parsed_version(f['fix_version'])) for f in group]
    if all(v is not None for _, v in parsed):
        return max(parsed, key=lambda pair: pair[1])[0]
    return max(group, key=lambda f: f['fix_version'])


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

def remediate_group(conn, group: list, token: str, repo_cache: dict):
    """Remediate one (repo, file_path, package) group - may be backed by
    several CVE findings for the same pin. Every finding_id in the group
    gets the same outcome recorded, so none of them are ever retried
    individually even though only one PR gets opened for the whole group."""
    finding_ids = [f['id'] for f in group]
    representative = group[0]
    owner = representative['username']
    repo = representative['repo']
    file_path = representative['file_path']

    def record_all(status, pr_url=None, branch_name=None, detail=None):
        for finding_id in finding_ids:
            record_remediation(conn, finding_id, status, pr_url=pr_url,
                                branch_name=branch_name, detail=detail)

    try:
        pkg_name, installed_version = representative['package'].rsplit(' ', 1)
    except ValueError:
        logger.warning(f"{owner}/{repo}: can't parse package/version from {representative['package']!r}")
        record_all('unsupported', detail='Unparseable package field')
        return

    best = pick_best_fix(group)
    cve_ids = sorted({f['cve_id'] for f in group if f['cve_id']})

    try:
        default_branch = get_default_branch(token, owner, repo, repo_cache)
        content, sha = get_file_contents(token, owner, repo, file_path, default_branch)
    except Exception as e:
        logger.error(f"{owner}/{repo}: failed to fetch {file_path}: {e}")
        record_all('failed', detail=str(e))
        return

    patched = patch_requirements(content, pkg_name, installed_version, best['fix_version'])
    if patched is None:
        logger.info(f"{owner}/{repo}: no line pins {pkg_name}=={installed_version} in {file_path}, skipping")
        record_all(
            'unsupported',
            detail=f"No line pinning {pkg_name}=={installed_version} found in {file_path}"
        )
        return

    branch = (
        f"baghguard/fix-{sanitize_branch_component(pkg_name)}"
        f"-{sanitize_branch_component(best['fix_version'])}"
    )
    cve_label = ', '.join(cve_ids) if cve_ids else 'security fix'

    try:
        create_branch(token, owner, repo, branch, default_branch)
        commit_file(
            token, owner, repo, file_path, branch, patched, sha,
            message=f"Bump {pkg_name} to {best['fix_version']} ({cve_label})",
        )
        severity_label = max(
            (f['severity'] for f in group),
            key=lambda s: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(s, 3)
        )
        descriptions = '\n\n'.join(sorted({f['description'] for f in group if f['description']}))
        pr_url, _ = open_pull_request(
            token, owner, repo, branch, default_branch,
            title=f"[BaghGuard] Fix {severity_label} {cve_label} in {pkg_name}".strip(),
            body=(
                f"BaghGuard detected {len(group)} "
                f"{'vulnerability' if len(group) == 1 else 'vulnerabilities'} in "
                f"`{pkg_name} {installed_version}` ({cve_label}) and opened this PR "
                f"automatically because you enabled auto-remediation.\n\n"
                f"**Fix:** bump to `{best['fix_version']}` (covers all of the above).\n\n"
                f"{descriptions}\n\n"
                f"Please review the diff before merging."
            ),
        )
    except Exception as e:
        logger.error(f"{owner}/{repo}: failed to open remediation PR for {pkg_name}: {e}")
        record_all('failed', branch_name=branch, detail=str(e))
        return

    logger.info(f"{owner}/{repo}: opened {pr_url} (covers {len(group)} finding(s))")
    record_all('open', pr_url=pr_url, branch_name=branch)


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

                groups = group_candidates([dict(f) for f in findings])
                logger.info(
                    f"{user['username']}: {len(findings)} finding(s) eligible for auto-remediation "
                    f"({len(groups)} PR(s) after grouping by package)"
                )
                repo_cache = {}
                for group in groups:
                    remediate_group(conn, group, user['access_token'], repo_cache)

            conn.close()

        except Exception as e:
            logger.error(f"Error in remediation loop: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
