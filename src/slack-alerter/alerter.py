#!/usr/bin/env python3
"""
BaghGuard Slack Alerter

Monitors PostgreSQL for new critical findings and sends alerts to Slack.
Integrates with OPA for policy-based alerting decisions.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Optional
import urllib.request
import urllib.error

import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('slack-alerter')

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'baghguard')
DB_USER = os.getenv('DB_USER', 'baghguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

# OPA configuration
OPA_URL = os.getenv('OPA_URL', 'http://opa:8181')

# Alert configuration
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '60'))
ALERT_SEVERITIES = os.getenv('ALERT_SEVERITIES', 'CRITICAL,HIGH').split(',')


def get_notify_users(conn) -> list:
    """Users with Slack alerts enabled and a webhook configured."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT u.id, u.username, n.slack_webhook
            FROM user_notify_settings n JOIN users u ON u.id = n.user_id
            WHERE n.slack_enabled = true
              AND n.slack_webhook IS NOT NULL AND n.slack_webhook != ''
        """)
        return cur.fetchall()


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
            f"{OPA_URL}/v1/data/baghguard/policy",
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


def send_slack_alert(findings: list, webhook_url: str):
    """Send alert to a user's Slack webhook."""
    if not webhook_url:
        logger.warning("No Slack webhook URL configured, logging alert instead")
        for f in findings:
            logger.info(f"ALERT: [{f['severity']}] {f['cve_id']} in {f['repo']} - {f['package']}")
        return

    # Build Slack message
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":warning: BaghGuard Security Alert",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(findings)} new security finding(s) detected*"
            }
        },
        {"type": "divider"}
    ]

    for finding in findings[:10]:  # Limit to 10 findings per message
        severity_emoji = {
            'CRITICAL': ':red_circle:',
            'HIGH': ':orange_circle:',
            'MEDIUM': ':yellow_circle:',
            'LOW': ':white_circle:'
        }.get(finding['severity'], ':white_circle:')

        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:* {severity_emoji} {finding['severity']}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Scanner:* {finding['scanner']}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Repository:* {finding['repo']}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*CVE:* {finding['cve_id'] or 'N/A'}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Package:* {finding['package'] or 'N/A'}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*File:* {finding['file_path'] or 'N/A'}"
                }
            ]
        })

        if finding.get('description'):
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": finding['description'][:300]
                }]
            })

        blocks.append({"type": "divider"})

    if len(findings) > 10:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"_...and {len(findings) - 10} more findings_"
            }]
        })

    payload = json.dumps({"blocks": blocks}).encode()

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            logger.info(f"Slack alert sent for {len(findings)} findings")
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Slack alert: {e}")


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
    """Main alerting loop - checks each opted-in user's findings and sends to their own webhook."""
    logger.info("Starting BaghGuard Slack Alerter")
    logger.info(f"Monitoring severities: {ALERT_SEVERITIES}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")
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

    # Per-user last check time, so a newly opted-in user still gets a
    # reasonable initial lookback instead of missing everything before now.
    last_check = {}

    while True:
        try:
            conn = get_db_connection()
            users = get_notify_users(conn)

            for user in users:
                since = last_check.get(user['id'], datetime.now() - timedelta(minutes=5))
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
                        send_slack_alert(alert_findings, user['slack_webhook'])

                last_check[user['id']] = datetime.now()

            conn.close()

        except Exception as e:
            logger.error(f"Error in alerting loop: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
