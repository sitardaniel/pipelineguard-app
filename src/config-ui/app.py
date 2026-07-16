#!/usr/bin/env python3
"""
BaghGuard Config UI

Web interface where each user signs in with their own GitHub account and
selects which of their own repos get scanned. Findings and notification
settings are isolated per user.
"""

import json
import mimetypes
import os
import re
import secrets
import smtplib
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from http import cookies
from http.server import HTTPServer, BaseHTTPRequestHandler

import psycopg2
from psycopg2.extras import RealDictCursor

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

# GitHub OAuth App credentials - see gitops/apps/config-ui/secret.yaml
GITHUB_OAUTH_CLIENT_ID = os.getenv('GITHUB_OAUTH_CLIENT_ID', '')
GITHUB_OAUTH_CLIENT_SECRET = os.getenv('GITHUB_OAUTH_CLIENT_SECRET', '')
OAUTH_REDIRECT_URI = os.getenv('OAUTH_REDIRECT_URI', 'http://localhost:8080/auth/callback')
# public_repo + read:user + user:email - scanning is scoped to each user's
# public repos, and user:email lets us capture a contact address at
# sign-in time to notify waitlisted users when BaghGuard goes live.
OAUTH_SCOPE = 'public_repo read:user user:email'

PORT = int(os.getenv('PORT', '8080'))
SESSION_COOKIE = 'pg_session'
SESSION_TTL_DAYS = 7

# Database configuration - same pattern as normalizer/alerters
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'baghguard')
DB_USER = os.getenv('DB_USER', 'baghguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

# scanner-config ConfigMap - still holds the merged TARGET_REPOS every
# scanner job reads; per-user notification settings now live in Postgres
# instead of this ConfigMap's NOTIFY_* keys.
TARGET_CONFIGMAP = os.getenv('TARGET_CONFIGMAP', 'scanner-config')
TARGET_NAMESPACE = os.getenv('TARGET_NAMESPACE', 'baghguard')

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# Waitlist / launch gating - see gitops/apps/config-ui/deployment.yaml
LAUNCH_AT = datetime.strptime(os.getenv('LAUNCH_AT', '2026-07-16T07:00:00Z'), '%Y-%m-%dT%H:%M:%SZ')
ADMIN_GITHUB_USERNAMES = {
    u.strip() for u in os.getenv('ADMIN_GITHUB_USERNAMES', '').split(',') if u.strip()
}

# SMTP configuration for the one-off "we're live" waitlist email - same
# relay/creds as email-alerter (see src/email-alerter/alerter.py), reused
# via the shared email-alerter-secret rather than a second copy.
SMTP_HOST = os.getenv('SMTP_HOST', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM', 'baghguard@localhost')


def has_access(user: dict) -> bool:
    """Whether a signed-in user may use the app, not just view its pages -
    checked in the data-mutating POST routes too, since a pending user
    still holds a valid session and could otherwise call them directly."""
    return user['username'] in ADMIN_GITHUB_USERNAMES or user['approval_status'] == 'approved'


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )


# --- Auth / sessions -------------------------------------------------------

def upsert_user(github_id: int, username: str, avatar_url: str, access_token: str, email: str) -> str:
    """Create or update the user record for this GitHub identity, return user id.

    Deliberately does not touch approval_status on conflict - a returning
    user keeps whatever waitlist status they already had; only brand new
    rows get the column's 'pending' default.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (github_id, username, avatar_url, access_token, email)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (github_id) DO UPDATE
                    SET username = EXCLUDED.username,
                        avatar_url = EXCLUDED.avatar_url,
                        access_token = EXCLUDED.access_token,
                        email = EXCLUDED.email
                RETURNING id
            """, (github_id, username, avatar_url, access_token, email))
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
    """Return the {id, username, avatar_url, access_token, approval_status, email}
    dict for a session token, or None."""
    if not token:
        return None
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT u.id, u.username, u.avatar_url, u.access_token, u.approval_status, u.email
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
    parts = f"{name}={value}; HttpOnly; Path=/; SameSite=Lax; Secure"
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


def fetch_primary_email(access_token: str) -> str:
    """The verified primary email for notifying this user when BaghGuard
    goes live - profile.email is only populated if the user made it public,
    so /user/emails (granted by the user:email scope) is the reliable source."""
    try:
        req = urllib.request.Request(
            "https://api.github.com/user/emails",
            headers={'Accept': 'application/vnd.github.v3+json', 'Authorization': f'Bearer {access_token}'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            emails = json.loads(response.read())
        for e in emails:
            if e.get('primary') and e.get('verified'):
                return e.get('email', '')
        for e in emails:
            if e.get('verified'):
                return e.get('email', '')
    except Exception as e:
        print(f"Error fetching primary email: {e}")
    return ''


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
                SELECT slack_webhook, slack_enabled, email_enabled, email_to, remediate_enabled
                FROM user_notify_settings WHERE user_id = %s
            """, (user_id,))
            row = cur.fetchone()
            if not row:
                return {
                    'slack_webhook': '', 'slack_enabled': False, 'email_enabled': False,
                    'email_to': [], 'remediate_enabled': False,
                }
            return {
                'slack_webhook': row['slack_webhook'] or '',
                'slack_enabled': row['slack_enabled'],
                'email_enabled': row['email_enabled'],
                'email_to': [a.strip() for a in (row['email_to'] or '').split(',') if a.strip()],
                'remediate_enabled': row['remediate_enabled'],
            }
    finally:
        conn.close()


def get_my_findings(user_id: str, limit: int = 1000) -> list:
    """The signed-in user's own findings (open and ignored), most severe and
    most recent first. Includes ignored findings so the UI can offer an
    Ignored view with an un-ignore action; the default UI filter hides them."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, repo, scanner, severity, cve_id, package, file_path,
                       description, scanned_at, status
                FROM findings
                WHERE owner_user_id = %s
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


def set_finding_status(user_id: str, finding_id: str, status: str):
    """Set a finding's status, scoped to the owning user so nobody can
    change another user's findings. Setting a non-open status stamps
    resolved_at (used both for display and so the trend chart's backlog
    calculation stops counting it); reopening clears resolved_at again."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE findings
                SET status = %s,
                    resolved_at = CASE WHEN %s != 'open' THEN now() ELSE NULL END
                WHERE id = %s AND owner_user_id = %s
            """, (status, status, finding_id, user_id))
            conn.commit()
    finally:
        conn.close()


def get_severity_trend(user_id: str, days: int = 30) -> list:
    """Open backlog size per severity for each of the last N days - counts
    findings that were detected on/before that day and not yet resolved by
    it, not just newly-detected findings."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                WITH day_series AS (
                    SELECT generate_series(
                        CURRENT_DATE - (%s - 1) * INTERVAL '1 day',
                        CURRENT_DATE,
                        INTERVAL '1 day'
                    )::date AS day
                ),
                severities AS (
                    SELECT unnest(ARRAY['CRITICAL','HIGH','MEDIUM','LOW']) AS severity
                )
                SELECT d.day, s.severity, COUNT(f.id) AS count
                FROM day_series d
                CROSS JOIN severities s
                LEFT JOIN findings f
                    ON f.owner_user_id = %s
                    AND f.severity = s.severity
                    AND f.scanned_at::date <= d.day
                    AND (f.resolved_at IS NULL OR f.resolved_at::date > d.day)
                GROUP BY d.day, s.severity
                ORDER BY d.day, s.severity
            """, (days, user_id))
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


# --- Waitlist / admin ---------------------------------------------------

def get_pending_users() -> list:
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, username, email, created_at
                FROM users WHERE approval_status = 'pending'
                ORDER BY created_at
            """)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_approval_counts() -> dict:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT approval_status, COUNT(*) FROM users GROUP BY approval_status
            """)
            counts = dict(cur.fetchall())
            return {'pending': counts.get('pending', 0), 'approved': counts.get('approved', 0)}
    finally:
        conn.close()


def set_approval_status(user_id: str, status: str) -> dict:
    """Returns the affected user's {username, email} so callers can notify them."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE users
                SET approval_status = %s,
                    approved_at = CASE WHEN %s = 'approved' THEN now() ELSE approved_at END
                WHERE id = %s
                RETURNING username, email
            """, (status, status, user_id))
            row = cur.fetchone()
            conn.commit()
            return dict(row) if row else {}
    finally:
        conn.close()


def request_approval_again(user_id: str) -> bool:
    """Move a rejected user back to 'pending' so they re-enter the waitlist
    queue. Scoped to rows currently 'rejected' - a no-op for users who are
    already pending or approved."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users SET approval_status = 'pending'
                WHERE id = %s AND approval_status = 'rejected'
            """, (user_id,))
            updated = cur.rowcount > 0
            conn.commit()
            return updated
    finally:
        conn.close()


def get_unnotified_pending_users() -> list:
    """Waitlisted users who haven't been sent the 'we're live' email yet."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, username, email FROM users
                WHERE approval_status = 'pending'
                  AND notified_live_at IS NULL
                  AND email IS NOT NULL AND email != ''
            """)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def mark_notified(user_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET notified_live_at = now() WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()


def _send_email(to_email: str, subject: str, body: str) -> bool:
    """Same smtplib pattern as email-alerter's send_email_alert
    (src/email-alerter/alerter.py) - one shared relay, no per-user setup."""
    if not SMTP_HOST:
        print(f"SMTP not configured, would have emailed {to_email}: {subject}")
        return False

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = ALERT_EMAIL_FROM
    msg['To'] = to_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, [to_email], msg.as_string())
        return True
    except smtplib.SMTPException as e:
        print(f"Failed to email {to_email}: {e}")
        return False


def send_launch_email(to_email: str, username: str) -> bool:
    return _send_email(
        to_email,
        'BaghGuard is live',
        f"Hi {username},\n\n"
        f"BaghGuard is live! You're on the waitlist and we'll let you know as soon as "
        f"your account is approved.\n\n- BaghGuard"
    )


def send_approval_email(to_email: str, username: str) -> bool:
    return _send_email(
        to_email,
        "You're approved for BaghGuard",
        f"Hi {username},\n\n"
        f"Your BaghGuard account has been approved. Log in and pick the repos "
        f"you'd like to start scanning.\n\n- BaghGuard"
    )


def save_user_data(user_id: str, repos: list, slack_webhook: str, slack_enabled: bool,
                    email_enabled: bool, email_to: list, remediate_enabled: bool):
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
                INSERT INTO user_notify_settings
                    (user_id, slack_webhook, slack_enabled, email_enabled, email_to, remediate_enabled)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE
                    SET slack_webhook = EXCLUDED.slack_webhook,
                        slack_enabled = EXCLUDED.slack_enabled,
                        email_enabled = EXCLUDED.email_enabled,
                        email_to = EXCLUDED.email_to,
                        remediate_enabled = EXCLUDED.remediate_enabled
            """, (user_id, slack_webhook, slack_enabled, email_enabled, ','.join(email_to), remediate_enabled))
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
    <title>BaghGuard - Sign In</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; display: flex;
            align-items: center; justify-content: center;
        }
        .card { text-align: center; }
        h1 { font-size: 2.2rem; margin-bottom: 10px; display: flex; align-items: center; justify-content: center; gap: 12px; }
        .logo-icon { height: 1.2em; width: auto; vertical-align: middle; }
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
        <h1><img src="/static/logo.png" alt="" class="logo-icon"> BaghGuard</h1>
        <p>Sign in to pick your own repos and see your own findings.</p>
        <a class="btn" href="/login">Sign in with GitHub</a>
    </div>
</body>
</html>
'''

COUNTDOWN_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BaghGuard - Coming Soon</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; display: flex;
            align-items: center; justify-content: center;
        }
        .card { text-align: center; }
        h1 { font-size: 2.2rem; margin-bottom: 10px; display: flex; align-items: center; justify-content: center; gap: 12px; }
        .logo-icon { height: 1.2em; width: auto; vertical-align: middle; }
        p { color: #888; margin-bottom: 30px; }
        .countdown { display: flex; gap: 20px; justify-content: center; margin-bottom: 30px; }
        .countdown .unit { min-width: 70px; }
        .countdown .num { font-size: 2.4rem; font-weight: 700; color: #4a9eff; font-variant-numeric: tabular-nums; }
        .countdown .label { color: #888; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
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
        <h1><img src="/static/logo.png" alt="" class="logo-icon"> BaghGuard</h1>
        <p>Automated security scanning for your repos. Launching soon.</p>
        <div class="countdown" id="countdown"></div>
        <a class="btn" href="/login">Join the waitlist</a>
    </div>
    <script>
        const launchAt = new Date('LAUNCH_AT_ISO').getTime();
        function render() {
            const diff = Math.max(0, launchAt - Date.now());
            const d = Math.floor(diff / 86400000);
            const h = Math.floor(diff % 86400000 / 3600000);
            const m = Math.floor(diff % 3600000 / 60000);
            const s = Math.floor(diff % 60000 / 1000);
            const units = [[d, 'Days'], [h, 'Hours'], [m, 'Min'], [s, 'Sec']];
            document.getElementById('countdown').innerHTML = units.map(([v, label]) =>
                `<div class="unit"><div class="num">${String(v).padStart(2, '0')}</div><div class="label">${label}</div></div>`
            ).join('');
            if (diff > 0) requestAnimationFrame(() => setTimeout(render, 1000));
            else location.reload();
        }
        render();
    </script>
</body>
</html>
'''

PENDING_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BaghGuard - Waitlisted</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; display: flex;
            align-items: center; justify-content: center;
        }
        .card { text-align: center; max-width: 420px; }
        h1 { font-size: 2.2rem; margin-bottom: 10px; display: flex; align-items: center; justify-content: center; gap: 12px; }
        .logo-icon { height: 1.2em; width: auto; vertical-align: middle; }
        p { color: #888; margin-bottom: 10px; line-height: 1.5; }
        .badge {
            display: inline-block; background: #3a2f0f; color: #fab219; border-radius: 20px;
            padding: 6px 16px; font-size: 0.85rem; font-weight: 600; margin-bottom: 20px;
        }
        .badge.rejected { background: #4a1515; color: #ff6b6b; }
        a { color: #4a9eff; text-decoration: none; }
        .btn {
            display: inline-block; background: #4a9eff; color: #fff; border: none;
            padding: 10px 20px; font-size: 0.9rem; font-weight: 600; border-radius: 8px;
            cursor: pointer; margin-bottom: 14px;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1><img src="/static/logo.png" alt="" class="logo-icon"> BaghGuard</h1>
        <div class="badge STATUS_CLASS">STATUS_LABEL</div>
        <p>Thanks for signing up. STATUS_MESSAGE</p>
        REQUEST_AGAIN
        <p><a href="/logout">Sign out</a></p>
    </div>
</body>
</html>
'''

ADMIN_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BaghGuard - Admin</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: #fff; padding: 40px 20px;
        }
        .container { max-width: 800px; margin: 0 auto; }
        .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        h1 { font-size: 2rem; display: flex; align-items: center; gap: 10px; }
        .logo-icon { height: 1.1em; width: auto; }
        a.back { color: #4a9eff; text-decoration: none; font-size: 0.9rem; }
        .panel { background: #0f0f1a; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
        .panel h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: 0.05em; color: #888; margin-bottom: 16px; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #222; }
        th { color: #888; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
        .empty-note { color: #666; font-size: 0.9rem; padding: 10px 0; }
        .btn { border: none; padding: 6px 14px; font-size: 0.8rem; font-weight: 600; border-radius: 6px; cursor: pointer; margin-right: 6px; }
        .btn-approve { background: #1e4620; color: #6ee06e; }
        .btn-reject { background: #4a1515; color: #ff6b6b; }
        .btn-notify {
            background: #4a9eff; color: #fff; padding: 12px 24px; font-size: 15px; border-radius: 8px;
        }
        .status { margin-top: 12px; font-size: 0.85rem; color: #888; }
        .stats { display: flex; gap: 16px; margin-bottom: 24px; }
        .stat { flex: 1; background: #0f0f1a; border-radius: 12px; padding: 16px 20px; }
        .stat-num { font-size: 1.8rem; font-weight: 700; font-variant-numeric: tabular-nums; }
        .stat-label { color: #888; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
        .stat.pending .stat-num { color: #fab219; }
        .stat.approved .stat-num { color: #6ee06e; }
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1><img src="/static/logo.png" alt="" class="logo-icon"> Admin</h1>
            <a class="back" href="/">&larr; Back to app</a>
        </div>

        <div class="stats">
            <div class="stat pending">
                <div class="stat-num">PENDING_COUNT</div>
                <div class="stat-label">On the waitlist</div>
            </div>
            <div class="stat approved">
                <div class="stat-num">APPROVED_COUNT</div>
                <div class="stat-label">Approved</div>
            </div>
        </div>

        <div class="panel">
            <h2>Waitlist &mdash; pending approval</h2>
            <div id="pendingBody"></div>
        </div>

        <div class="panel">
            <h2>Launch notification</h2>
            <div id="notifySection"></div>
        </div>
    </div>

    <script>
        const pending = PENDING_JSON;
        const launched = LAUNCHED_JSON;

        function escapeHtml(s) {
            const div = document.createElement('div');
            div.textContent = s == null ? '' : String(s);
            return div.innerHTML;
        }

        function renderPending() {
            const body = document.getElementById('pendingBody');
            if (!pending.length) {
                body.innerHTML = '<div class="empty-note">No one waiting on approval.</div>';
                return;
            }
            body.innerHTML = `
                <table>
                    <tr><th>User</th><th>Email</th><th>Requested</th><th></th></tr>
                    ${pending.map(u => `
                        <tr data-id="${escapeHtml(u.id)}">
                            <td>${escapeHtml(u.username)}</td>
                            <td>${escapeHtml(u.email || '—')}</td>
                            <td>${u.created_at ? escapeHtml(new Date(u.created_at).toLocaleDateString()) : '—'}</td>
                            <td>
                                <button class="btn btn-approve" onclick="decide('${u.id}', 'approved')">Approve</button>
                                <button class="btn btn-reject" onclick="decide('${u.id}', 'rejected')">Reject</button>
                            </td>
                        </tr>
                    `).join('')}
                </table>
            `;
        }

        function decide(id, status) {
            fetch('/admin/' + (status === 'approved' ? 'approve' : 'reject'), {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: id})
            })
            .then(r => r.json().then(data => ({ok: r.ok, data})))
            .then(({ok, data}) => {
                if (!ok) { alert('Error: ' + data.error); return; }
                const idx = pending.findIndex(u => u.id === id);
                if (idx > -1) pending.splice(idx, 1);
                renderPending();
                document.querySelector('.stat.pending .stat-num').textContent = pending.length;
                if (status === 'approved') {
                    const approvedEl = document.querySelector('.stat.approved .stat-num');
                    approvedEl.textContent = Number(approvedEl.textContent) + 1;
                }
            })
            .catch(err => alert('Error: ' + err));
        }

        function renderNotify() {
            const section = document.getElementById('notifySection');
            if (!launched) {
                section.innerHTML = '<div class="empty-note">Unlocks once BaghGuard has launched.</div>';
                return;
            }
            section.innerHTML = `
                <button class="btn btn-notify" id="notifyBtn" onclick="notifyWaitlist()">Notify waitlist we're live</button>
                <div class="status" id="notifyStatus"></div>
            `;
        }

        function notifyWaitlist() {
            const btn = document.getElementById('notifyBtn');
            const status = document.getElementById('notifyStatus');
            btn.disabled = true;
            fetch('/admin/notify-waitlist', {method: 'POST'})
                .then(r => r.json().then(data => ({ok: r.ok, data})))
                .then(({ok, data}) => {
                    status.textContent = ok ? `Emailed ${data.count} waitlisted user(s).` : 'Error: ' + data.error;
                    btn.disabled = false;
                })
                .catch(err => { status.textContent = 'Error: ' + err; btn.disabled = false; });
        }

        renderPending();
        renderNotify();
    </script>
</body>
</html>
'''

NAV_HTML = '''
        <div class="nav-tabs">
            <a class="nav-tab NAV_REPOS_ACTIVE" href="/">Repos</a>
            <a class="nav-tab NAV_FINDINGS_ACTIVE" href="/findings">Findings</a>
        </div>
'''

REPOS_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BaghGuard - Select Repos</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
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
        .logo-icon { height: 1.1em; width: auto; vertical-align: middle; }
        .subtitle { color: #888; margin-bottom: 30px; }
        .nav-tabs { display: flex; gap: 8px; margin-bottom: 24px; }
        .nav-tab {
            color: #888; text-decoration: none; padding: 8px 16px; border-radius: 8px;
            font-size: 0.9rem; font-weight: 600;
        }
        .nav-tab:hover { color: #ccc; }
        .nav-tab.active { color: #fff; background: #1e3a5f; }
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
        .notify-section {
            background: #0f0f1a;
            border-radius: 12px;
            padding: 20px;
            margin-top: 30px;
        }
        .notify-section h2 {
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
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1><img src="/static/logo.png" alt="" class="logo-icon"> BaghGuard</h1>
            <div class="user-badge">
                <img src="USER_AVATAR" alt="">
                <span>USER_NAME</span>
                ADMIN_LINK
                <a href="/logout">Sign out</a>
            </div>
        </div>
        NAV_MARKUP
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
            <label class="check-row">
                <input type="checkbox" id="remediateEnabled">
                Open fix PRs automatically
            </label>
            <div class="field-hint">Critical/high findings with a known fix in a plain requirements.txt pin only. Opens a real PR on your repo using your GitHub login - review before merging.</div>
        </div>

        <button class="btn" id="saveBtn" onclick="saveSelection()">Save Selection</button>
        <div class="status" id="status"></div>
    </div>

    <script>
        const repos = REPOS_JSON;
        const selected = SELECTED_JSON;
        const notifySettings = NOTIFY_JSON;

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
            document.getElementById('remediateEnabled').checked = notifySettings.remediate_enabled;
            updateNotifyUI();
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
                email_to: document.getElementById('emailTo').value.split(',').map(s => s.trim()).filter(Boolean),
                remediate_enabled: document.getElementById('remediateEnabled').checked
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
    </script>
</body>
</html>
'''

FINDINGS_HTML = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>BaghGuard - Findings</title>
    <link rel="icon" type="image/png" href="/static/logo.png">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #fff;
            padding: 40px 20px;
        }
        .container { max-width: 1000px; margin: 0 auto; }
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
        .logo-icon { height: 1.1em; width: auto; vertical-align: middle; }
        .subtitle { color: #888; margin-bottom: 30px; }
        .nav-tabs { display: flex; gap: 8px; margin-bottom: 24px; }
        .nav-tab {
            color: #888; text-decoration: none; padding: 8px 16px; border-radius: 8px;
            font-size: 0.9rem; font-weight: 600;
        }
        .nav-tab:hover { color: #ccc; }
        .nav-tab.active { color: #fff; background: #1e3a5f; }

        /* --- Open Issues dashboard ------------------------------------- */
        :root {
            --status-critical: #d03b3b;
            --status-serious:  #ec835a;
            --status-warning:  #fab219;
            --status-good:     #0ca30c;
            --series-blue:     #4a9eff;
            --ink-primary:     #fff;
            --ink-secondary:   #b0b0b8;
            --ink-muted:       #888;
        }

        .findings-section {
            background: #0f0f1a;
            border-radius: 12px;
            padding: 20px;
        }
        .findings-section h2 {
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #888;
            margin-bottom: 16px;
        }

        .stat-row {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }
        .stat-tile {
            background: #16162a;
            border-radius: 10px;
            padding: 14px 16px;
            border-left: 3px solid var(--tile-accent, #333);
        }
        .stat-tile .stat-label {
            color: var(--ink-secondary);
            font-size: 0.78rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .stat-tile .stat-value {
            color: var(--ink-primary);
            font-size: 1.9rem;
            font-weight: 700;
            margin-top: 4px;
        }

        .chart-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .chart-card {
            background: #16162a;
            border-radius: 12px;
            padding: 18px 20px;
        }
        .chart-card h3 {
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--ink-muted);
            margin-bottom: 14px;
            font-weight: 600;
        }
        .bar-row { display: flex; align-items: center; gap: 10px; padding: 5px 0; }
        .bar-row .bar-label {
            width: 108px; flex: 0 0 auto; font-size: 0.82rem; color: var(--ink-secondary);
            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .bar-track {
            flex: 1 1 auto; height: 20px; border-radius: 4px;
            background: rgba(255,255,255,0.06); position: relative; cursor: default;
        }
        .bar-fill {
            height: 100%; border-radius: 4px; min-width: 4px;
            transition: filter 0.15s;
        }
        .bar-row:hover .bar-fill, .bar-row:focus-within .bar-fill { filter: brightness(1.2); }
        .bar-value {
            width: 34px; flex: 0 0 auto; text-align: right;
            font-variant-numeric: tabular-nums; font-weight: 600; color: var(--ink-primary);
            font-size: 0.85rem;
        }
        .chart-empty { color: var(--ink-muted); font-size: 0.85rem; padding: 10px 0; }

        .trend-card { margin-bottom: 24px; }
        .trend-svg { width: 100%; height: 200px; display: block; margin-top: 4px; }
        .trend-legend { display: flex; gap: 16px; margin-bottom: 8px; }
        .trend-legend-item { display: flex; align-items: center; gap: 6px; font-size: 0.82rem; color: var(--ink-secondary); }
        .trend-legend-dot { width: 9px; height: 9px; border-radius: 50%; flex: 0 0 auto; }

        .chart-tooltip {
            position: fixed; pointer-events: none; z-index: 50;
            background: #1a1a2e; border: 1px solid #333; border-radius: 6px;
            padding: 6px 10px; font-size: 0.8rem; color: var(--ink-primary);
            display: none; box-shadow: 0 4px 12px rgba(0,0,0,0.4);
        }
        .chart-tooltip .tt-value { font-weight: 700; }
        .chart-tooltip .tt-label { color: var(--ink-secondary); margin-left: 4px; }

        .issues-filter-row {
            display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
            margin-bottom: 16px;
        }
        .sev-chip {
            border: 1px solid #333; background: transparent; border-radius: 20px;
            padding: 5px 14px; font-size: 0.8rem; font-weight: 600; cursor: pointer;
            color: var(--ink-secondary); display: flex; align-items: center; gap: 6px;
        }
        .sev-chip .dot { width: 8px; height: 8px; border-radius: 50%; }
        .sev-chip.active { color: #fff; border-color: currentColor; background: rgba(255,255,255,0.06); }
        .status-chip {
            border: 1px solid #333; background: transparent; border-radius: 20px;
            padding: 5px 14px; font-size: 0.8rem; font-weight: 600; cursor: pointer;
            color: var(--ink-secondary);
        }
        .status-chip.active { color: #fff; border-color: #4a9eff; background: rgba(74,158,255,0.12); }
        .btn-link {
            background: none; border: none; color: #4a9eff; cursor: pointer;
            font-size: 0.8rem; font-weight: 600; padding: 0; white-space: nowrap;
        }
        .btn-link:hover { text-decoration: underline; }
        .issues-search {
            flex: 1 1 200px; min-width: 160px; padding: 8px 12px; font-size: 0.85rem;
            border: 2px solid #333; border-radius: 8px; background: #1a1a2e; color: #fff;
        }
        .issues-search:focus { outline: none; border-color: #4a9eff; }
        .issues-count { color: var(--ink-muted); font-size: 0.8rem; margin-bottom: 10px; }

        .findings-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; table-layout: fixed; }
        .findings-table th, .findings-table td { text-align: left; padding: 6px 10px; border-bottom: 1px solid #222; }
        .findings-table th {
            color: #888; font-weight: 600; text-transform: uppercase; font-size: 0.75rem;
            cursor: pointer; user-select: none; white-space: nowrap;
        }
        .findings-table th:hover { color: #ccc; }
        .findings-table th .sort-arrow { opacity: 0.5; margin-left: 3px; }
        .findings-table th.sorted .sort-arrow { opacity: 1; }
        .findings-table td.finding-desc {
            color: #aaa; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        }
        .sev-CRITICAL { color: var(--status-critical); }
        .sev-HIGH { color: var(--status-serious); }
        .sev-MEDIUM { color: var(--status-warning); }
        .sev-LOW { color: var(--status-good); }
        .empty-note { color: #666; font-size: 0.9rem; padding: 16px 0; }

        @media (max-width: 700px) {
            .stat-row { grid-template-columns: repeat(2, 1fr); }
            .chart-row { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <h1><img src="/static/logo.png" alt="" class="logo-icon"> BaghGuard</h1>
            <div class="user-badge">
                <img src="USER_AVATAR" alt="">
                <span>USER_NAME</span>
                ADMIN_LINK
                <a href="/logout">Sign out</a>
            </div>
        </div>
        NAV_MARKUP
        <p class="subtitle">Vulnerabilities found across your scanned repositories</p>

        <div class="findings-section">
            <div class="stat-row" id="statRow"></div>

            <div class="chart-row">
                <div class="chart-card">
                    <h3>By severity</h3>
                    <div id="severityChart"></div>
                </div>
                <div class="chart-card">
                    <h3>By scanner</h3>
                    <div id="scannerChart"></div>
                </div>
                <div class="chart-card">
                    <h3>By repository</h3>
                    <div id="repoChart"></div>
                </div>
            </div>

            <div class="chart-card trend-card">
                <h3>Open backlog &mdash; last 30 days</h3>
                <div class="trend-legend" id="trendLegend"></div>
                <svg id="trendChart" class="trend-svg" viewBox="0 0 600 200" preserveAspectRatio="none"></svg>
            </div>

            <div class="issues-filter-row" id="statusFilterRow"></div>
            <div class="issues-filter-row" id="sevFilterRow"></div>
            <input type="text" class="issues-search" id="issuesSearch"
                   placeholder="Search repo, package, CVE, description..." oninput="renderIssues()">

            <div class="issues-count" id="issuesCount"></div>
            <div id="findingsBody"></div>
        </div>

        <div class="chart-tooltip" id="chartTooltip"></div>
    </div>

    <script>
        const findings = FINDINGS_JSON;
        const trend = TREND_JSON;

        function escapeHtml(s) {
            const div = document.createElement('div');
            div.textContent = s == null ? '' : String(s);
            return div.innerHTML;
        }

        const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
        const SEVERITY_COLOR = {
            CRITICAL: 'var(--status-critical)',
            HIGH: 'var(--status-serious)',
            MEDIUM: 'var(--status-warning)',
            LOW: 'var(--status-good)',
        };
        const SEVERITY_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3};

        const issuesFilter = {
            severities: new Set(SEVERITY_ORDER),
            status: 'open',
        };
        const issuesSort = {column: 'severity', dir: 'asc'};

        function getFilteredFindings() {
            const q = document.getElementById('issuesSearch').value.trim().toLowerCase();
            return findings.filter(f => {
                if ((f.status || 'open') !== issuesFilter.status) return false;
                if (!issuesFilter.severities.has(f.severity)) return false;
                if (!q) return true;
                const haystack = [f.repo, f.package, f.cve_id, f.description, f.file_path]
                    .filter(Boolean).join(' ').toLowerCase();
                return haystack.includes(q);
            });
        }

        function renderStatusFilterToggle() {
            const row = document.getElementById('statusFilterRow');
            const counts = {
                open: findings.filter(f => (f.status || 'open') === 'open').length,
                ignored: findings.filter(f => f.status === 'ignored').length,
            };
            row.innerHTML = ['open', 'ignored'].map(s => `
                <button type="button" class="status-chip ${issuesFilter.status === s ? 'active' : ''}"
                        onclick="setStatusFilter('${s}')">
                    ${s === 'open' ? 'Open' : 'Ignored'} (${counts[s]})
                </button>
            `).join('');
        }

        function setStatusFilter(status) {
            issuesFilter.status = status;
            renderStatusFilterToggle();
            renderIssues();
        }

        function setFindingStatus(id, status) {
            fetch('/findings/status', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({id: id, status: status})
            })
            .then(r => r.json().then(data => ({ok: r.ok, data})))
            .then(({ok, data}) => {
                if (!ok) {
                    alert('Error: ' + data.error);
                    return;
                }
                const f = findings.find(f => f.id === id);
                if (f) f.status = status;
                renderStatusFilterToggle();
                renderIssues();
            })
            .catch(err => alert('Error: ' + err));
        }

        function renderSevFilterChips() {
            const row = document.getElementById('sevFilterRow');
            row.innerHTML = SEVERITY_ORDER.map(sev => `
                <button type="button" class="sev-chip active" data-sev="${sev}"
                        style="color:${SEVERITY_COLOR[sev]}" onclick="toggleSevFilter('${sev}')">
                    <span class="dot" style="background:${SEVERITY_COLOR[sev]}"></span>${sev}
                </button>
            `).join('');
        }

        function toggleSevFilter(sev) {
            if (issuesFilter.severities.has(sev)) {
                issuesFilter.severities.delete(sev);
            } else {
                issuesFilter.severities.add(sev);
            }
            document.querySelectorAll('.sev-chip').forEach(chip => {
                chip.classList.toggle('active', issuesFilter.severities.has(chip.dataset.sev));
            });
            renderIssues();
        }

        function showTooltip(evt, valueText, labelText) {
            const tip = document.getElementById('chartTooltip');
            tip.innerHTML = '';
            const value = document.createElement('span');
            value.className = 'tt-value';
            value.textContent = valueText;
            const label = document.createElement('span');
            label.className = 'tt-label';
            label.textContent = labelText;
            tip.appendChild(value);
            tip.appendChild(label);
            tip.style.display = 'block';
            tip.style.left = (evt.clientX + 14) + 'px';
            tip.style.top = (evt.clientY + 14) + 'px';
        }

        function hideTooltip() {
            document.getElementById('chartTooltip').style.display = 'none';
        }

        function renderBarChart(containerId, rows, opts) {
            const el = document.getElementById(containerId);
            if (!rows.length) {
                el.innerHTML = '<div class="chart-empty">No open issues.</div>';
                return;
            }
            const max = Math.max(1, ...rows.map(r => r.value));
            el.innerHTML = rows.map(r => `
                <div class="bar-row" tabindex="0" data-label="${escapeHtml(r.label)}" data-value="${r.value}">
                    <div class="bar-label" title="${escapeHtml(r.label)}">${escapeHtml(r.label)}</div>
                    <div class="bar-track">
                        <div class="bar-fill" style="width:${(r.value / max * 100).toFixed(1)}%; background:${r.color}"></div>
                    </div>
                    <div class="bar-value">${r.value}</div>
                </div>
            `).join('');
            el.querySelectorAll('.bar-row').forEach(row => {
                const onMove = evt => showTooltip(evt, row.dataset.value, row.dataset.label);
                row.addEventListener('pointermove', onMove);
                row.addEventListener('pointerenter', onMove);
                row.addEventListener('pointerleave', hideTooltip);
                row.addEventListener('focus', evt => showTooltip(evt, row.dataset.value, row.dataset.label));
                row.addEventListener('blur', hideTooltip);
            });
        }

        function renderTrendChart(trendRows) {
            const svg = document.getElementById('trendChart');
            const legend = document.getElementById('trendLegend');

            legend.innerHTML = SEVERITY_ORDER.map(sev => `
                <div class="trend-legend-item">
                    <span class="trend-legend-dot" style="background:${SEVERITY_COLOR[sev]}"></span>
                    ${sev}
                </div>
            `).join('');

            if (!trendRows.length) {
                svg.innerHTML = '<text x="300" y="100" text-anchor="middle" fill="var(--ink-muted)" font-size="12">No history yet.</text>';
                return;
            }

            const days = [...new Set(trendRows.map(r => r.day))].sort();
            const bySeverity = {};
            SEVERITY_ORDER.forEach(sev => { bySeverity[sev] = days.map(() => 0); });
            trendRows.forEach(r => {
                const idx = days.indexOf(r.day);
                if (idx !== -1 && bySeverity[r.severity]) bySeverity[r.severity][idx] = r.count;
            });

            const maxCount = Math.max(1, ...Object.values(bySeverity).flat());
            const w = 600, h = 200, pad = 6;
            const xStep = days.length > 1 ? (w - 2 * pad) / (days.length - 1) : 0;

            const toPoint = (idx, value) => {
                const x = pad + idx * xStep;
                const y = h - pad - (value / maxCount) * (h - 2 * pad);
                return [x, y];
            };

            let svgContent = '';
            SEVERITY_ORDER.forEach(sev => {
                const series = bySeverity[sev];
                const points = series.map((v, i) => toPoint(i, v).join(',')).join(' ');
                svgContent += `<polyline points="${points}" fill="none" stroke="${SEVERITY_COLOR[sev]}" stroke-width="2" />`;
                series.forEach((v, i) => {
                    const [x, y] = toPoint(i, v);
                    svgContent += `<circle cx="${x}" cy="${y}" r="2.5" fill="${SEVERITY_COLOR[sev]}"><title>${escapeHtml(days[i])} — ${sev}: ${v}</title></circle>`;
                });
            });
            svg.innerHTML = svgContent;
        }

        function renderStatTiles(filtered) {
            const counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0};
            filtered.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
            const totalLabel = issuesFilter.status === 'ignored' ? 'Total ignored' : 'Total open';
            const tiles = [
                {label: totalLabel, value: filtered.length, accent: '#4a9eff'},
                {label: 'Critical', value: counts.CRITICAL, accent: SEVERITY_COLOR.CRITICAL},
                {label: 'High', value: counts.HIGH, accent: SEVERITY_COLOR.HIGH},
                {label: 'Medium', value: counts.MEDIUM, accent: SEVERITY_COLOR.MEDIUM},
                {label: 'Low', value: counts.LOW, accent: SEVERITY_COLOR.LOW},
            ];
            document.getElementById('statRow').innerHTML = tiles.map(t => `
                <div class="stat-tile" style="--tile-accent:${t.accent}">
                    <div class="stat-label">${t.label}</div>
                    <div class="stat-value">${t.value}</div>
                </div>
            `).join('');
            return counts;
        }

        function renderCharts(filtered, counts) {
            renderBarChart('severityChart', SEVERITY_ORDER.map(sev => ({
                label: sev, value: counts[sev], color: SEVERITY_COLOR[sev],
            })));

            const byScanner = {};
            filtered.forEach(f => { byScanner[f.scanner] = (byScanner[f.scanner] || 0) + 1; });
            const scannerRows = Object.entries(byScanner)
                .sort((a, b) => b[1] - a[1])
                .map(([scanner, count]) => ({label: scanner, value: count, color: 'var(--series-blue)'}));
            renderBarChart('scannerChart', scannerRows);

            const byRepo = {};
            filtered.forEach(f => { byRepo[f.repo] = (byRepo[f.repo] || 0) + 1; });
            const repoRows = Object.entries(byRepo)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8)
                .map(([repo, count]) => ({label: repo, value: count, color: 'var(--series-blue)'}));
            renderBarChart('repoChart', repoRows);
        }

        function sortFindings(rows) {
            const {column, dir} = issuesSort;
            const mul = dir === 'asc' ? 1 : -1;
            return rows.slice().sort((a, b) => {
                let av, bv;
                if (column === 'severity') { av = SEVERITY_RANK[a.severity]; bv = SEVERITY_RANK[b.severity]; }
                else if (column === 'scanned_at') { av = a.scanned_at || ''; bv = b.scanned_at || ''; }
                else { av = (a[column] || '').toLowerCase(); bv = (b[column] || '').toLowerCase(); }
                if (av < bv) return -1 * mul;
                if (av > bv) return 1 * mul;
                return 0;
            });
        }

        function sortBy(column) {
            if (issuesSort.column === column) {
                issuesSort.dir = issuesSort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                issuesSort.column = column;
                issuesSort.dir = 'asc';
            }
            renderIssues();
        }

        function renderFindingsTable(rows) {
            const body = document.getElementById('findingsBody');
            if (!rows.length) {
                body.innerHTML = `<div class="empty-note">No ${issuesFilter.status} findings match these filters.</div>`;
                return;
            }
            const cols = [
                {key: 'severity', label: 'Severity'},
                {key: 'scanner', label: 'Scanner'},
                {key: 'repo', label: 'Repo'},
                {key: 'cve_id', label: 'CVE / Package'},
                {key: 'scanned_at', label: 'Scanned'},
            ];
            const headerHtml = cols.map(c => {
                const sorted = issuesSort.column === c.key;
                const arrow = sorted ? (issuesSort.dir === 'asc' ? '▲' : '▼') : '▲';
                return `<th class="${sorted ? 'sorted' : ''}" onclick="sortBy('${c.key}')">${c.label}<span class="sort-arrow">${arrow}</span></th>`;
            }).join('') + '<th>Details</th><th></th>';

            const rowsHtml = rows.map(f => `
                <tr data-id="${escapeHtml(f.id)}">
                    <td class="sev-${f.severity}">${escapeHtml(f.severity)}</td>
                    <td>${escapeHtml(f.scanner)}</td>
                    <td>${escapeHtml(f.repo)}</td>
                    <td>${escapeHtml(f.cve_id || f.package || '—')}</td>
                    <td>${f.scanned_at ? escapeHtml(new Date(f.scanned_at).toLocaleDateString()) : '—'}</td>
                    <td class="finding-desc">${escapeHtml(f.file_path || '')}${f.description ? ' – ' + escapeHtml(f.description) : ''}</td>
                    <td>${f.status === 'ignored'
                        ? `<button type="button" class="btn-link" onclick="setFindingStatus('${f.id}', 'open')">Un-ignore</button>`
                        : `<button type="button" class="btn-link" onclick="setFindingStatus('${f.id}', 'ignored')">Ignore</button>`}</td>
                </tr>
            `).join('');

            body.innerHTML = `
                <table class="findings-table">
                    <tr>${headerHtml}</tr>
                    ${rowsHtml}
                </table>
            `;
        }

        function renderIssues() {
            const filtered = getFilteredFindings();
            const counts = renderStatTiles(filtered);
            renderCharts(filtered, counts);
            const totalForStatus = findings.filter(f => (f.status || 'open') === issuesFilter.status).length;
            document.getElementById('issuesCount').textContent =
                `Showing ${filtered.length} of ${totalForStatus} ${issuesFilter.status} issues`;
            renderFindingsTable(sortFindings(filtered));
        }

        renderSevFilterChips();
        renderStatusFilterToggle();
        renderIssues();
        renderTrendChart(trend);
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

        if self.path.startswith('/static/'):
            self.serve_static(self.path[len('/static/'):])
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
            launched = datetime.utcnow() >= LAUNCH_AT
            page = LOGIN_HTML if launched else COUNTDOWN_HTML.replace('LAUNCH_AT_ISO', LAUNCH_AT.isoformat() + 'Z')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(page.encode())
            return

        is_admin = user['username'] in ADMIN_GITHUB_USERNAMES

        if self.path == '/admin':
            if not is_admin:
                self.send_error_json(403, "Admin access only")
                return
            counts = get_approval_counts()
            html = (ADMIN_HTML
                    .replace('PENDING_JSON', json.dumps(get_pending_users(), default=str))
                    .replace('LAUNCHED_JSON', json.dumps(datetime.utcnow() >= LAUNCH_AT))
                    .replace('PENDING_COUNT', str(counts['pending']))
                    .replace('APPROVED_COUNT', str(counts['approved'])))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html.encode())
            return

        if not has_access(user):
            status = user['approval_status']
            request_again = (
                '<form method="POST" action="/request-again">'
                '<button class="btn" type="submit">Request approval again</button></form>'
                if status == 'rejected' else ''
            )
            page = (PENDING_HTML
                    .replace('STATUS_CLASS', 'rejected' if status == 'rejected' else '')
                    .replace('STATUS_LABEL', 'Not approved' if status == 'rejected' else 'On the waitlist')
                    .replace('STATUS_MESSAGE',
                             "Your request wasn't approved. You can ask for another review below."
                             if status == 'rejected'
                             else "You'll be able to log in on Thursday, once an admin approves your account.")
                    .replace('REQUEST_AGAIN', request_again))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(page.encode())
            return

        if self.path == '/findings':
            findings = get_my_findings(user['id'])
            trend = get_severity_trend(user['id'])
            nav = (NAV_HTML
                    .replace('NAV_REPOS_ACTIVE', '')
                    .replace('NAV_FINDINGS_ACTIVE', 'active'))
            html = (FINDINGS_HTML
                    .replace('FINDINGS_JSON', json.dumps(findings, default=str))
                    .replace('TREND_JSON', json.dumps(trend, default=str))
                    .replace('NAV_MARKUP', nav)
                    .replace('USER_AVATAR', user['avatar_url'] or '')
                    .replace('ADMIN_LINK', '<a href="/admin">Admin</a>' if is_admin else '')
                    .replace('USER_NAME', user['username']))
        else:
            repos = get_user_repos(user['access_token'])
            selected = get_selected_repos(user['id'])
            notify = get_notify_settings(user['id'])
            nav = (NAV_HTML
                    .replace('NAV_REPOS_ACTIVE', 'active')
                    .replace('NAV_FINDINGS_ACTIVE', ''))
            html = (REPOS_HTML
                    .replace('REPOS_JSON', json.dumps(repos))
                    .replace('SELECTED_JSON', json.dumps(selected))
                    .replace('NOTIFY_JSON', json.dumps(notify))
                    .replace('NAV_MARKUP', nav)
                    .replace('USER_AVATAR', user['avatar_url'] or '')
                    .replace('ADMIN_LINK', '<a href="/admin">Admin</a>' if is_admin else '')
                    .replace('USER_NAME', user['username']))

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_static(self, rel_path):
        rel_path = urllib.parse.unquote(rel_path)
        full_path = os.path.normpath(os.path.join(STATIC_DIR, rel_path))
        if not full_path.startswith(STATIC_DIR + os.sep) or not os.path.isfile(full_path):
            self.send_response(404)
            self.end_headers()
            return

        content_type = mimetypes.guess_type(full_path)[0] or 'application/octet-stream'
        with open(full_path, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', 'public, max-age=86400')
        self.end_headers()
        self.wfile.write(data)

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
            email = fetch_primary_email(access_token)
            user_id = upsert_user(
                github_id=profile['id'],
                username=profile['login'],
                avatar_url=profile.get('avatar_url', ''),
                access_token=access_token,
                email=email,
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
            if not has_access(user):
                self.send_error_json(403, "Your account is still on the waitlist")
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
            remediate_enabled = bool(notify.get('remediate_enabled', False))

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

            save_user_data(user['id'], repos, slack_webhook, slack_enabled, email_enabled, email_to, remediate_enabled)

            try:
                regenerate_target_repos_configmap()
            except Exception as e:
                print(f"Could not update ConfigMap: {e}")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'count': len(repos)}).encode())
            return

        if self.path == '/findings/status':
            session_token = parse_cookie(self, SESSION_COOKIE)
            user = get_session_user(session_token)
            if not user:
                self.send_error_json(401, "Not signed in")
                return
            if not has_access(user):
                self.send_error_json(403, "Your account is still on the waitlist")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)

            finding_id = data.get('id', '')
            status = data.get('status', '')
            if status not in ('open', 'ignored'):
                self.send_error_json(400, "Invalid status")
                return

            set_finding_status(user['id'], finding_id, status)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
            return

        if self.path == '/request-again':
            session_token = parse_cookie(self, SESSION_COOKIE)
            user = get_session_user(session_token)
            if not user:
                self.send_error_json(401, "Not signed in")
                return

            request_approval_again(user['id'])

            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if self.path in ('/admin/approve', '/admin/reject'):
            session_token = parse_cookie(self, SESSION_COOKIE)
            user = get_session_user(session_token)
            if not user or user['username'] not in ADMIN_GITHUB_USERNAMES:
                self.send_error_json(403, "Admin access only")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            target_id = data.get('id', '')
            if not target_id:
                self.send_error_json(400, "Missing id")
                return

            approving = self.path == '/admin/approve'
            target = set_approval_status(target_id, 'approved' if approving else 'rejected')
            if approving and target.get('email'):
                send_approval_email(target['email'], target['username'])

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok'}).encode())
            return

        if self.path == '/admin/notify-waitlist':
            session_token = parse_cookie(self, SESSION_COOKIE)
            user = get_session_user(session_token)
            if not user or user['username'] not in ADMIN_GITHUB_USERNAMES:
                self.send_error_json(403, "Admin access only")
                return

            if datetime.utcnow() < LAUNCH_AT:
                self.send_error_json(400, "Can't notify the waitlist before launch")
                return

            sent = 0
            for waiting in get_unnotified_pending_users():
                if send_launch_email(waiting['email'], waiting['username']):
                    sent += 1
                mark_notified(waiting['id'])

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'count': sent}).encode())
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
    print(f"Starting BaghGuard Config UI on port {PORT}")
    print(f"OAuth configured: {bool(GITHUB_OAUTH_CLIENT_ID)}")
    server = HTTPServer(('0.0.0.0', PORT), ConfigUIHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()
