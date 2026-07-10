#!/usr/bin/env python3
"""
PipelineGuard Config UI

Web interface where each user signs in with their own GitHub account and
selects which of their own repos get scanned. Findings and notification
settings are isolated per user.
"""

import json
import os
import re
import secrets
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from http import cookies
from http.server import HTTPServer, BaseHTTPRequestHandler

import psycopg2
from psycopg2.extras import RealDictCursor

# GitHub OAuth App credentials - see gitops/apps/config-ui/deployment.yaml
GITHUB_OAUTH_CLIENT_ID = os.getenv('GITHUB_OAUTH_CLIENT_ID', '')
GITHUB_OAUTH_CLIENT_SECRET = os.getenv('GITHUB_OAUTH_CLIENT_SECRET', '')
OAUTH_REDIRECT_URI = os.getenv('OAUTH_REDIRECT_URI', 'http://localhost:8080/auth/callback')
# public_repo + read:user only - scanning is scoped to each user's public
# repos, so we never need write access or private-repo contents.
OAUTH_SCOPE = 'public_repo read:user'

PORT = int(os.getenv('PORT', '8080'))
SESSION_COOKIE = 'pg_session'
SESSION_TTL_DAYS = 7

# Database configuration - same pattern as normalizer/alerters
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'pipelineguard')
DB_USER = os.getenv('DB_USER', 'pipelineguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

# scanner-config ConfigMap - still holds the merged TARGET_REPOS every
# scanner job reads; per-user notification settings now live in Postgres
# instead of this ConfigMap's NOTIFY_* keys.
TARGET_CONFIGMAP = os.getenv('TARGET_CONFIGMAP', 'scanner-config')
TARGET_NAMESPACE = os.getenv('TARGET_NAMESPACE', 'pipelineguard')

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )


# --- Auth / sessions -------------------------------------------------------

def upsert_user(github_id: int, username: str, avatar_url: str, access_token: str) -> str:
    """Create or update the user record for this GitHub identity, return user id."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (github_id, username, avatar_url, access_token)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (github_id) DO UPDATE
                    SET username = EXCLUDED.username,
                        avatar_url = EXCLUDED.avatar_url,
                        access_token = EXCLUDED.access_token
                RETURNING id
            """, (github_id, username, avatar_url, access_token))
            user_id = cur.fetchone()[0]
            conn.commit()
            return user_id
    finally:
        conn.close()


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_TTL_DAYS)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
                (token, user_id, expires_at)
            )
            conn.commit()
    finally:
        conn.close()
    return token


def get_session_user(token: str):
    """Return the {id, username, avatar_url, access_token} dict for a session token, or None."""
    if not token:
        return None
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT u.id, u.username, u.avatar_url, u.access_token
                FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token = %s AND s.expires_at > now()
            """, (token,))
            return cur.fetchone()
    finally:
        conn.close()


def delete_session(token: str):
    if not token:
        return
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
            conn.commit()
    finally:
        conn.close()


def parse_cookie(handler, name: str):
    raw = handler.headers.get('Cookie', '')
    if not raw:
        return None
    jar = cookies.SimpleCookie()
    jar.load(raw)
    morsel = jar.get(name)
    return morsel.value if morsel else None


def set_cookie(handler, name: str, value: str, max_age: int = None):
    parts = f"{name}={value}; HttpOnly; Path=/; SameSite=Lax"
    if max_age is not None:
        parts += f"; Max-Age={max_age}"
    handler.send_header('Set-Cookie', parts)


# --- GitHub API --------------------------------------------------------------

def get_user_repos(access_token: str) -> list:
    """Fetch the authenticated user's own public repos."""
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/user/repos?per_page=100&page={page}&sort=updated&affiliation=owner&visibility=public"
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': f'Bearer {access_token}',
        }
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read())
                if not data:
                    break
                repos.extend(data)
                page += 1
                if len(data) < 100:
                    break
        except Exception as e:
            print(f"Error fetching repos: {e}")
            break
    return repos


def exchange_code_for_token(code: str) -> str:
    url = "https://github.com/login/oauth/access_token"
    body = urllib.parse.urlencode({
        'client_id': GITHUB_OAUTH_CLIENT_ID,
        'client_secret': GITHUB_OAUTH_CLIENT_SECRET,
        'code': code,
        'redirect_uri': OAUTH_REDIRECT_URI,
    }).encode()
    req = urllib.request.Request(url, data=body, headers={'Accept': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=10) as response:
        data = json.loads(response.read())
        return data.get('access_token', '')


def fetch_github_profile(access_token: str) -> dict:
    req = urllib.request.Request(
        "https://api.github.com/user",
        headers={'Accept': 'application/vnd.github.v3+json', 'Authorization': f'Bearer {access_token}'}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


# --- Per-user data -----------------------------------------------------------

def get_selected_repos(user_id: str) -> list:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT repo_url FROM user_repos WHERE user_id = %s", (user_id,))
            return [row[0] for row in cur.fetchall()]
    finally:
        conn.close()


def get_notify_settings(user_id: str) -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT slack_webhook, slack_enabled, email_enabled, email_to
                FROM user_notify_settings WHERE user_id = %s
            """, (user_id,))
            row = cur.fetchone()
            if not row:
                return {'slack_webhook': '', 'slack_enabled': False, 'email_enabled': False, 'email_to': []}
            return {
                'slack_webhook': row['slack_webhook'] or '',
                'slack_enabled': row['slack_enabled'],
                'email_enabled': row['email_enabled'],
                'email_to': [a.strip() for a in (row['email_to'] or '').split(',') if a.strip()],
            }
    finally:
        conn.close()


def get_my_findings(user_id: str, limit: int = 100) -> list:
    """The signed-in user's own open findings, most severe and most recent first."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT repo, scanner, severity, cve_id, package, file_path,
                       description, scanned_at
                FROM findings
                WHERE owner_user_id = %s AND status = 'open'
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        ELSE 4
                    END,
                    scanned_at DESC
                LIMIT %s
            """, (user_id, limit))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def save_user_data(user_id: str, repos: list, slack_webhook: str, slack_enabled: bool,
                    email_enabled: bool, email_to: list):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_repos WHERE user_id = %s", (user_id,))
            for repo_url in repos:
                cur.execute(
                    "INSERT INTO user_repos (user_id, repo_url) VALUES (%s, %s)",
                    (user_id, repo_url)
                )
            cur.execute("""
                INSERT INTO user_notify_settings (user_id, slack_webhook, slack_enabled, email_enabled, email_to)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE
                    SET slack_webhook = EXCLUDED.slack_webhook,
                        slack_enabled = EXCLUDED.slack_enabled,
                        email_enabled = EXCLUDED.email_enabled,
                        email_to = EXCLUDED.email_to
            """, (user_id, slack_webhook, slack_enabled, email_enabled, ','.join(email_to)))
            conn.commit()
    finally:
        conn.close()


def regenerate_target_repos_configmap():
    """Rebuild TARGET_REPOS as the union of every user's selected repos.

    Each line is "username::repo_url" so the scanner CronJobs can tag which
    user owns each clone, which normalizer uses to attribute findings.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.username, r.repo_url
                FROM user_repos r JOIN users u ON u.id = r.user_id
                ORDER BY u.username, r.repo_url
            """)
            lines = [f"{username}::{repo_url}" for username, repo_url in cur.fetchall()]
    finally:
        conn.close()

    try:
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        cm = v1.read_namespaced_config_map(TARGET_CONFIGMAP, TARGET_NAMESPACE)
        cm.data['TARGET_REPOS'] = '\n'.join(lines)
        v1.patch_namespaced_config_map(TARGET_CONFIGMAP, TARGET_NAMESPACE, cm)
        print(f"Updated TARGET_REPOS with {len(lines)} repos across all users")
    except ImportError:
        print("kubernetes package not installed, skipping ConfigMap update")


# --- HTML --------------------------------------------------------------------

LOGIN_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PipelineGuard - Sign In</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; display: flex;
            align-items: center; justify-content: center;
        }
        .card { text-align: center; }
        h1 { font-size: 2.2rem; margin-bottom: 10px; }
        p { color: #888; margin-bottom: 30px; }
        .btn {
            background: #24292e; color: #fff; border: none; padding: 14px 28px;
            font-size: 16px; font-weight: 600; border-radius: 8px; cursor: pointer;
            text-decoration: none; display: inline-flex; align-items: center; gap: 10px;
        }
        .btn:hover { background: #333; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🛡️ PipelineGuard</h1>
        <p>Sign in to pick your own repos and see your own findings.</p>
        <a class="btn" href="/login">Sign in with GitHub</a>
    </div>
</body>
</html>
'''

HTML_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PipelineGuard - Select Repos</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
            padding: 40px 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .top-bar {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px;
        }
        .user-badge { display: flex; align-items: center; gap: 10px; color: #ccc; font-size: 0.9rem; }
        .user-badge img { width: 28px; height: 28px; border-radius: 50%; }
        .user-badge a { color: #4a9eff; text-decoration: none; margin-left: 10px; }
        h1 {
            font-size: 2rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .subtitle { color: #888; margin-bottom: 30px; }
        .search-box {
            width: 100%;
            padding: 12px 16px;
            font-size: 16px;
            border: 2px solid #333;
            border-radius: 8px;
            background: #0f0f1a;
            color: #fff;
            margin-bottom: 20px;
        }
        .search-box:focus { outline: none; border-color: #4a9eff; }
        .repo-list {
            background: #0f0f1a;
            border-radius: 12px;
            overflow: hidden;
            max-height: 500px;
            overflow-y: auto;
        }
        .repo-item {
            display: flex;
            align-items: center;
            padding: 16px 20px;
            border-bottom: 1px solid #222;
            cursor: pointer;
            transition: background 0.2s;
        }
        .repo-item:hover { background: #1a1a2e; }
        .repo-item.selected { background: #1e3a5f; }
        .repo-item input {
            width: 20px;
            height: 20px;
            margin-right: 15px;
            cursor: pointer;
        }
        .repo-info { flex: 1; }
        .repo-name { font-weight: 600; font-size: 1.1rem; }
        .repo-desc { color: #888; font-size: 0.9rem; margin-top: 4px; }
        .repo-meta {
            display: flex;
            gap: 15px;
            margin-top: 6px;
            font-size: 0.8rem;
            color: #666;
        }
        .btn {
            background: #4a9eff;
            color: #fff;
            border: none;
            padding: 14px 28px;
            font-size: 16px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 20px;
            transition: background 0.2s;
        }
        .btn:hover { background: #3a8eef; }
        .btn:disabled { background: #444; cursor: not-allowed; }
        .status {
            margin-top: 15px;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }
        .status.success { display: block; background: #1e4620; }
        .status.error { display: block; background: #4a1515; }
        .selected-count {
            background: #4a9eff;
            color: #fff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9rem;
        }
        .header-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .notify-section, .findings-section {
            background: #0f0f1a;
            border-radius: 12px;
            padding: 20px;
            margin-top: 30px;
        }
        .notify-section h2, .findings-section h2 {
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #888;
            margin-bottom: 16px;
        }
        .check-row {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 0;
            cursor: pointer;
        }
        .check-row input { width: 18px; height: 18px; cursor: pointer; }
        .text-input {
            width: 100%;
            padding: 10px 14px;
            font-size: 15px;
            border: 2px solid #333;
            border-radius: 8px;
            background: #1a1a2e;
            color: #fff;
            margin-top: 8px;
            display: none;
        }
        .text-input.visible { display: block; }
        .text-input:focus { outline: none; border-color: #4a9eff; }
        .field-hint { color: #666; font-size: 0.8rem; margin-top: 6px; }
        .findings-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }
        .findings-table th, .findings-table td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #222; }
        .findings-table th { color: #888; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        .findings-table td.finding-desc {
            color: #aaa; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .sev-CRITICAL { color: #ff4d4d; }
        .sev-HIGH { color: #ff9f4d; }
        .sev-MEDIUM { color: #ffd24d; }
        .sev-LOW { color: #999; }
        .empty-note { color: #666; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1>PipelineGuard</h1>
            <div class="user-badge">
                <img src="USER_AVATAR" alt="">
                <span>USER_NAME</span>
                <a href="/logout">Sign out</a>
            </div>
        </div>
        <p class="subtitle">Select repositories to scan for security vulnerabilities</p>

        <input type="text" class="search-box" id="search" placeholder="Search repositories..." oninput="filterRepos()">

        <div class="header-row">
            <span id="selectedCount" class="selected-count">0 selected</span>
        </div>

        <div class="repo-list" id="repoList">
            <!-- Repos will be inserted here -->
        </div>

        <div class="notify-section">
            <h2>Notifications</h2>
            <label class="check-row">
                <input type="checkbox" id="slackEnabled" onchange="updateNotifyUI()">
                Send alerts to Slack
            </label>
            <input type="text" class="text-input" id="slackWebhook" placeholder="https://hooks.slack.com/services/...">
            <label class="check-row">
                <input type="checkbox" id="emailEnabled" onchange="updateNotifyUI()">
                Send alerts by email
            </label>
            <input type="text" class="text-input" id="emailTo" placeholder="you@example.com, teammate@example.com">
            <div class="field-hint">Critical and high-severity findings only. Comma-separate multiple email addresses.</div>
        </div>

        <div class="findings-section">
            <h2>My Findings</h2>
            <div id="findingsBody"></div>
        </div>

        <button class="btn" id="saveBtn" onclick="saveSelection()">Save Selection</button>
        <div class="status" id="status"></div>
    </div>

    <script>
        const repos = REPOS_JSON;
        const selected = SELECTED_JSON;
        const notifySettings = NOTIFY_JSON;
        const findings = FINDINGS_JSON;

        function renderRepos(filter = '') {
            const list = document.getElementById('repoList');
            const filtered = repos.filter(r =>
                r.name.toLowerCase().includes(filter.toLowerCase()) ||
                (r.description && r.description.toLowerCase().includes(filter.toLowerCase()))
            );

            list.innerHTML = filtered.map(repo => {
                const isSelected = selected.includes(repo.html_url);
                return `
                    <label class="repo-item ${isSelected ? 'selected' : ''}" data-url="${repo.html_url}">
                        <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="toggleRepo(this, '${repo.html_url}')">
                        <div class="repo-info">
                            <div class="repo-name">${repo.name}</div>
                            ${repo.description ? `<div class="repo-desc">${repo.description}</div>` : ''}
                            <div class="repo-meta">
                                <span>${repo.language || 'Unknown'}</span>
                                <span>${repo.stargazers_count} stars</span>
                                <span>Updated ${new Date(repo.updated_at).toLocaleDateString()}</span>
                            </div>
                        </div>
                    </label>
                `;
            }).join('');

            updateCount();
        }

        function toggleRepo(checkbox, url) {
            const item = checkbox.closest('.repo-item');
            if (checkbox.checked) {
                selected.push(url);
                item.classList.add('selected');
            } else {
                const idx = selected.indexOf(url);
                if (idx > -1) selected.splice(idx, 1);
                item.classList.remove('selected');
            }
            updateCount();
        }

        function updateCount() {
            document.getElementById('selectedCount').textContent = selected.length + ' selected';
        }

        function filterRepos() {
            renderRepos(document.getElementById('search').value);
        }

        function updateNotifyUI() {
            document.getElementById('slackWebhook').classList.toggle('visible', document.getElementById('slackEnabled').checked);
            document.getElementById('emailTo').classList.toggle('visible', document.getElementById('emailEnabled').checked);
        }

        function initNotifySettings() {
            document.getElementById('slackEnabled').checked = notifySettings.slack_enabled;
            document.getElementById('slackWebhook').value = notifySettings.slack_webhook;
            document.getElementById('emailEnabled').checked = notifySettings.email_enabled;
            document.getElementById('emailTo').value = notifySettings.email_to.join(', ');
            updateNotifyUI();
        }

        function escapeHtml(s) {
            const div = document.createElement('div');
            div.textContent = s == null ? '' : String(s);
            return div.innerHTML;
        }

        function renderFindings() {
            const body = document.getElementById('findingsBody');
            if (!findings.length) {
                body.innerHTML = '<div class="empty-note">No open findings for your repos yet.</div>';
                return;
            }
            const rows = findings.map(f => `
                <tr>
                    <td class="sev-${f.severity}">${escapeHtml(f.severity)}</td>
                    <td>${escapeHtml(f.scanner)}</td>
                    <td>${escapeHtml(f.repo)}</td>
                    <td>${escapeHtml(f.cve_id || f.package || '—')}</td>
                    <td class="finding-desc">${escapeHtml(f.file_path || '')}${f.description ? ' – ' + escapeHtml(f.description) : ''}</td>
                </tr>
            `).join('');
            body.innerHTML = `
                <table class="findings-table">
                    <tr><th>Severity</th><th>Scanner</th><th>Repo</th><th>CVE / Package</th><th>Details</th></tr>
                    ${rows}
                </table>
            `;
        }

        function saveSelection() {
            const btn = document.getElementById('saveBtn');
            const status = document.getElementById('status');
            btn.disabled = true;
            btn.textContent = 'Saving...';

            const notify = {
                slack_enabled: document.getElementById('slackEnabled').checked,
                slack_webhook: document.getElementById('slackWebhook').value.trim(),
                email_enabled: document.getElementById('emailEnabled').checked,
                email_to: document.getElementById('emailTo').value.split(',').map(s => s.trim()).filter(Boolean)
            };

            fetch('/save', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({repos: selected, notify: notify})
            })
            .then(r => r.json().then(data => ({ok: r.ok, data})))
            .then(({ok, data}) => {
                status.className = ok ? 'status success' : 'status error';
                status.textContent = ok
                    ? 'Saved! Scanners and alerters will use these settings on next run.'
                    : 'Error: ' + data.error;
                btn.textContent = 'Save Selection';
                btn.disabled = false;
            })
            .catch(err => {
                status.className = 'status error';
                status.textContent = 'Error saving: ' + err;
                btn.textContent = 'Save Selection';
                btn.disabled = false;
            });
        }

        renderRepos();
        initNotifySettings();
        renderFindings();
    </script>
</body>
</html>
'''


class ConfigUIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')
            return

        if self.path == '/login':
            state = secrets.token_urlsafe(16)
            params = urllib.parse.urlencode({
                'client_id': GITHUB_OAUTH_CLIENT_ID,
                'redirect_uri': OAUTH_REDIRECT_URI,
                'scope': OAUTH_SCOPE,
                'state': state,
            })
            self.send_response(302)
            self.send_header('Location', f'https://github.com/login/oauth/authorize?{params}')
            set_cookie(self, 'pg_oauth_state', state, max_age=600)
            self.end_headers()
            return

        if self.path.startswith('/auth/callback'):
            self.handle_oauth_callback()
            return

        if self.path == '/logout':
            token = parse_cookie(self, SESSION_COOKIE)
            delete_session(token)
            self.send_response(302)
            self.send_header('Location', '/')
            set_cookie(self, SESSION_COOKIE, '', max_age=0)
            self.end_headers()
            return

        # Everything else requires a signed-in session
        session_token = parse_cookie(self, SESSION_COOKIE)
        user = get_session_user(session_token)
        if not user:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(LOGIN_HTML.encode())
            return

        repos = get_user_repos(user['access_token'])
        selected = get_selected_repos(user['id'])
        notify = get_notify_settings(user['id'])
        findings = get_my_findings(user['id'])

        html = (HTML_TEMPLATE
                .replace('REPOS_JSON', json.dumps(repos))
                .replace('SELECTED_JSON', json.dumps(selected))
                .replace('NOTIFY_JSON', json.dumps(notify))
                .replace('FINDINGS_JSON', json.dumps(findings, default=str))
                .replace('USER_AVATAR', user['avatar_url'] or '')
                .replace('USER_NAME', user['username']))

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_oauth_callback(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get('code', [None])[0]
        state = query.get('state', [None])[0]
        expected_state = parse_cookie(self, 'pg_oauth_state')

        if not code or not state or state != expected_state:
            self.send_error_json(400, "Invalid OAuth callback (missing or mismatched state)")
            return

        try:
            access_token = exchange_code_for_token(code)
            if not access_token:
                self.send_error_json(400, "GitHub did not return an access token")
                return
            profile = fetch_github_profile(access_token)
            user_id = upsert_user(
                github_id=profile['id'],
                username=profile['login'],
                avatar_url=profile.get('avatar_url', ''),
                access_token=access_token,
            )
            session_token = create_session(user_id)
        except Exception as e:
            self.send_error_json(500, f"OAuth login failed: {e}")
            return

        self.send_response(302)
        self.send_header('Location', '/')
        set_cookie(self, SESSION_COOKIE, session_token, max_age=SESSION_TTL_DAYS * 86400)
        set_cookie(self, 'pg_oauth_state', '', max_age=0)
        self.end_headers()

    def do_POST(self):
        if self.path == '/save':
            session_token = parse_cookie(self, SESSION_COOKIE)
            user = get_session_user(session_token)
            if not user:
                self.send_error_json(401, "Not signed in")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            repos = data.get('repos', [])
            notify = data.get('notify', {})
            slack_enabled = bool(notify.get('slack_enabled', False))
            slack_webhook = notify.get('slack_webhook', '').strip()
            email_enabled = bool(notify.get('email_enabled', False))
            email_to = [a.strip() for a in notify.get('email_to', []) if a.strip()]

            if slack_enabled and not slack_webhook:
                self.send_error_json(400, "Enable Slack alerts requires a webhook URL.")
                return

            if email_enabled:
                invalid = [a for a in email_to if not EMAIL_RE.match(a)]
                if not email_to:
                    self.send_error_json(400, "Enable email alerts requires at least one email address.")
                    return
                if invalid:
                    self.send_error_json(400, f"Invalid email address: {invalid[0]}")
                    return

            save_user_data(user['id'], repos, slack_webhook, slack_enabled, email_enabled, email_to)

            try:
                regenerate_target_repos_configmap()
            except Exception as e:
                print(f"Could not update ConfigMap: {e}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'count': len(repos)}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def send_error_json(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    def log_message(self, format, *args):
        print(f"{self.address_string()} - {format % args}")


def main():
    print(f"Starting PipelineGuard Config UI on port {PORT}")
    print(f"OAuth configured: {bool(GITHUB_OAUTH_CLIENT_ID)}")
    server = HTTPServer(('0.0.0.0', PORT), ConfigUIHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()
