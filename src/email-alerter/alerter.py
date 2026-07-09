#!/usr/bin/env python3
"""
PipelineGuard Email Alerter

Monitors PostgreSQL for new critical findings and emails alerts via SMTP.
Integrates with OPA for policy-based alerting decisions, same as the
Slack alerter.
"""

import logging
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import urllib.request

import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('email-alerter')

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'pipelineguard')
DB_USER = os.getenv('DB_USER', 'pipelineguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

# SMTP configuration - one shared relay for everyone; only the recipient
# and the findings content vary per user (asking each user to bring their
# own Gmail App Password isn't realistic).
SMTP_HOST = os.getenv('SMTP_HOST', '')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM', 'pipelineguard@localhost')

# OPA configuration
OPA_URL = os.getenv('OPA_URL', 'http://opa:8181')

# Alert configuration
# Unlike the Slack alerter (60s poll, alerts fire near-instantly), email checks
# once a day across all scanned repos and sends a single daily digest.
CHECK_INTERVAL_SECONDS = int(os.getenv('CHECK_INTERVAL_SECONDS', str(24 * 3600)))
ALERT_SEVERITIES = os.getenv('ALERT_SEVERITIES', 'CRITICAL,HIGH').split(',')


def get_notify_users(conn) -> list:
    """Users with email alerts enabled and at least one recipient address."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT u.id, u.username, n.email_to
            FROM user_notify_settings n JOIN users u ON u.id = n.user_id
            WHERE n.email_enabled = true
              AND n.email_to IS NOT NULL AND n.email_to != ''
        """)
        return cur.fetchall()

SEVERITY_COLOR = {
    'CRITICAL': '#d1242f',
    'HIGH': '#bf8700',
    'MEDIUM': '#9a6700',
    'LOW': '#57606a',
}


def get_db_connection():
    """Create database connection."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def check_opa_policy(finding: dict) -> dict:
    """Check OPA policy for a finding."""
    try:
        data = json.dumps({"input": finding}, default=str).encode()
        req = urllib.request.Request(
            f"{OPA_URL}/v1/data/pipelineguard/policy",
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read())
            return result.get('result', {})
    except Exception as e:
        logger.error(f"OPA check failed: {e}")
        return {'alert': True}  # Default to alert if OPA is unavailable


def build_email_body(findings: list) -> str:
    """Build an HTML email body summarizing findings."""
    rows = []
    for finding in findings[:25]:  # Cap the table to keep the email readable
        color = SEVERITY_COLOR.get(finding['severity'], '#57606a')
        rows.append(f"""
        <tr>
          <td style="color:{color};font-weight:bold;">{finding['severity']}</td>
          <td>{finding['scanner']}</td>
          <td>{finding['repo']}</td>
          <td>{finding['cve_id'] or 'N/A'}</td>
          <td>{finding['package'] or 'N/A'}</td>
          <td>{finding['file_path'] or 'N/A'}</td>
        </tr>""")

    extra_note = ""
    if len(findings) > 25:
        extra_note = f"<p><em>...and {len(findings) - 25} more findings not shown.</em></p>"

    return f"""
    <html>
      <body>
        <h2>&#9888; PipelineGuard Security Alert</h2>
        <p><strong>{len(findings)} new security finding(s) detected</strong></p>
        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;">
          <tr style="background:#f6f8fa;">
            <th>Severity</th><th>Scanner</th><th>Repository</th>
            <th>CVE</th><th>Package</th><th>File</th>
          </tr>
          {''.join(rows)}
        </table>
        {extra_note}
      </body>
    </html>
    """


def send_email_alert(findings: list, recipients: list):
    """Send alert email via SMTP to the given recipients."""
    if not SMTP_HOST or not recipients:
        logger.warning("SMTP not configured (SMTP_HOST/recipients), logging alert instead")
        for f in findings:
            logger.info(f"ALERT: [{f['severity']}] {f['cve_id']} in {f['repo']} - {f['package']}")
        return

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"[PipelineGuard] {len(findings)} new security finding(s)"
    msg['From'] = ALERT_EMAIL_FROM
    msg['To'] = ', '.join(recipients)
    msg.attach(MIMEText(build_email_body(findings), 'html'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_EMAIL_FROM, recipients, msg.as_string())
        logger.info(f"Email alert sent to {recipients} for {len(findings)} findings")
    except smtplib.SMTPException as e:
        logger.error(f"Failed to send email alert: {e}")


def get_new_findings(conn, since: datetime, owner_user_id) -> list:
    """Get this user's new findings since their last check."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT id, repo, scanner, severity, cve_id, package,
                   file_path, line_number, description, fix_version,
                   status, scanned_at
            FROM findings
            WHERE scanned_at > %s
              AND status = 'open'
              AND severity = ANY(%s)
              AND owner_user_id = %s
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    ELSE 4
                END,
                scanned_at DESC
        """, (since, ALERT_SEVERITIES, owner_user_id))
        return cur.fetchall()


def main():
    """Main alerting loop - checks each opted-in user's findings and emails them their own digest."""
    logger.info("Starting PipelineGuard Email Alerter")
    logger.info(f"Monitoring severities: {ALERT_SEVERITIES}")
    logger.info(f"Check interval: {CHECK_INTERVAL_SECONDS}s (~{CHECK_INTERVAL_SECONDS / 3600:.1f}h)")
    logger.info(f"SMTP configured: {bool(SMTP_HOST)}")
    logger.info(f"OPA URL: {OPA_URL}")

    # Wait for database
    for i in range(30):
        try:
            conn = get_db_connection()
            conn.close()
            logger.info("Database connection successful")
            break
        except Exception as e:
            logger.warning(f"Waiting for database... ({i+1}/30)")
            time.sleep(2)
    else:
        logger.error("Could not connect to database")
        sys.exit(1)

    # Per-user last check time. Look back a full interval on each user's
    # first check so it covers a whole day, not just a few minutes.
    last_check = {}

    while True:
        try:
            conn = get_db_connection()
            users = get_notify_users(conn)

            for user in users:
                since = last_check.get(user['id'], datetime.now() - timedelta(seconds=CHECK_INTERVAL_SECONDS))
                findings = get_new_findings(conn, since, user['id'])

                if findings:
                    logger.info(f"{user['username']}: found {len(findings)} new findings to evaluate")

                    alert_findings = []
                    for finding in findings:
                        policy_result = check_opa_policy(dict(finding))
                        if policy_result.get('alert', False):
                            alert_findings.append(finding)
                            for msg in policy_result.get('violation', []):
                                logger.info(f"Policy violation: {msg}")

                    if alert_findings:
                        recipients = [a.strip() for a in user['email_to'].split(',') if a.strip()]
                        send_email_alert(alert_findings, recipients)

                last_check[user['id']] = datetime.now()

            conn.close()

        except Exception as e:
            logger.error(f"Error in alerting loop: {e}")

        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == '__main__':
    main()
