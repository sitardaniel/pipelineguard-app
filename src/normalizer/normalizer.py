#!/usr/bin/env python3
"""
PipelineGuard Result Normalizer

Watches for scan results from Trivy, Checkov, Gitleaks, and Grype,
normalizes them to a common schema, and stores them in PostgreSQL.
"""

import json
import os
import re
import sys
import time
import uuid
import glob
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import psycopg2
from psycopg2.extras import execute_values

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('normalizer')

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'postgresql')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'pipelineguard')
DB_USER = os.getenv('DB_USER', 'pipelineguard')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'localdevpassword')

# Results directory
RESULTS_DIR = os.getenv('RESULTS_DIR', '/results')
PROCESSED_DIR = os.getenv('PROCESSED_DIR', '/results/processed')
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '30'))


def get_db_connection():
    """Create database connection."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def normalize_trivy(data: dict, filename: str) -> list:
    """Normalize Trivy scan results."""
    findings = []
    owner_username, repo = extract_repo_from_filename(filename)

    # Handle filesystem scan results
    results = data.get('Results', [])
    for result in results:
        target = result.get('Target', '')
        vulns = result.get('Vulnerabilities', [])

        for vuln in vulns:
            findings.append({
                'repo': repo,
                'owner_username': owner_username,
                'scanner': 'trivy',
                'severity': vuln.get('Severity', 'UNKNOWN'),
                'cve_id': vuln.get('VulnerabilityID'),
                'package': f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}",
                'file_path': target,
                'line_number': None,
                'description': vuln.get('Title', vuln.get('Description', ''))[:500],
                'fix_version': vuln.get('FixedVersion'),
            })

        # Handle misconfigurations
        misconfigs = result.get('Misconfigurations', [])
        for misconfig in misconfigs:
            findings.append({
                'repo': repo,
                'owner_username': owner_username,
                'scanner': 'trivy',
                'severity': misconfig.get('Severity', 'UNKNOWN'),
                'cve_id': misconfig.get('ID'),
                'package': misconfig.get('Type', ''),
                'file_path': target,
                'line_number': None,
                'description': misconfig.get('Title', misconfig.get('Message', ''))[:500],
                'fix_version': None,
            })

    return findings


def normalize_checkov(data: dict, filename: str) -> list:
    """Normalize Checkov scan results."""
    findings = []
    owner_username, repo = extract_repo_from_filename(filename)

    # Handle different Checkov output formats
    checks = data if isinstance(data, list) else [data]

    for check_result in checks:
        failed_checks = check_result.get('results', {}).get('failed_checks', [])

        for check in failed_checks:
            severity = check.get('severity', 'MEDIUM')
            if severity is None:
                severity = 'MEDIUM'

            findings.append({
                'repo': repo,
                'owner_username': owner_username,
                'scanner': 'checkov',
                'severity': severity.upper(),
                'cve_id': check.get('check_id'),
                'package': check.get('check_type', 'terraform'),
                'file_path': check.get('file_path', ''),
                'line_number': check.get('file_line_range', [None])[0],
                'description': check.get('check_name', '')[:500],
                'fix_version': None,
            })

    return findings


def normalize_gitleaks(data: list, filename: str) -> list:
    """Normalize Gitleaks scan results."""
    findings = []
    owner_username, repo = extract_repo_from_filename(filename)

    if not isinstance(data, list):
        data = []

    for leak in data:
        findings.append({
            'repo': repo,
            'owner_username': owner_username,
            'scanner': 'gitleaks',
            'severity': 'HIGH',  # All secrets are high severity
            'cve_id': None,
            'package': leak.get('RuleID', 'secret'),
            'file_path': leak.get('File', ''),
            'line_number': leak.get('StartLine'),
            'description': f"Secret detected: {leak.get('Description', leak.get('RuleID', 'Unknown'))}",
            'fix_version': None,
        })

    return findings


def normalize_grype(data: dict, filename: str) -> list:
    """Normalize Grype scan results."""
    findings = []
    owner_username, repo = extract_repo_from_filename(filename)

    matches = data.get('matches', [])

    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})

        findings.append({
            'repo': repo,
            'owner_username': owner_username,
            'scanner': 'grype',
            'severity': vuln.get('severity', 'UNKNOWN'),
            'cve_id': vuln.get('id'),
            'package': f"{artifact.get('name', '')} {artifact.get('version', '')}",
            'file_path': artifact.get('locations', [{}])[0].get('path', ''),
            'line_number': None,
            'description': vuln.get('description', '')[:500] if vuln.get('description') else '',
            'fix_version': vuln.get('fix', {}).get('versions', [None])[0] if vuln.get('fix') else None,
        })

    return findings


_TIMESTAMP_SUFFIX_RE = re.compile(r'^(.*)-\d{8}-\d{6}$')
_SCANNER_PREFIXES = ('trivy-', 'checkov-', 'gitleaks-', 'grype-')


def extract_repo_from_filename(filename: str) -> tuple:
    """Extract (owner_username, repo_name) from a scan result filename.

    Filenames look like <scanner>-<clone_dir>-<YYYYMMDD>-<HHMMSS>.json,
    where <clone_dir> is exactly what the git-clone init container named the
    checkout: "<username>__<reponame>". Strip the known scanner prefix and
    timestamp suffix rather than positionally split on "-", since repo names
    themselves contain hyphens (a naive split previously mangled
    "pipelineguard-app" into the repo name "pipelineguard").
    """
    stem = os.path.basename(filename)
    if stem.endswith('.json'):
        stem = stem[:-len('.json')]

    for prefix in _SCANNER_PREFIXES:
        if stem.startswith(prefix):
            stem = stem[len(prefix):]
            break

    match = _TIMESTAMP_SUFFIX_RE.match(stem)
    clone_dir_name = match.group(1) if match else stem

    if '__' in clone_dir_name:
        username, repo_name = clone_dir_name.split('__', 1)
        return username, repo_name
    return None, clone_dir_name or 'unknown'


def process_file(filepath: str) -> list:
    """Process a single scan result file."""
    filename = os.path.basename(filepath)
    logger.info(f"Processing {filename}")

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON in {filename}: {e}")
        return []
    except Exception as e:
        logger.error(f"Failed to read {filename}: {e}")
        return []

    # Determine scanner type from filename
    if 'trivy' in filename:
        return normalize_trivy(data, filename)
    elif 'checkov' in filename:
        return normalize_checkov(data, filename)
    elif 'gitleaks' in filename:
        return normalize_gitleaks(data, filename)
    elif 'grype' in filename:
        return normalize_grype(data, filename)
    else:
        logger.warning(f"Unknown scanner type for {filename}")
        return []


def insert_findings(findings: list):
    """Insert findings into PostgreSQL, attributing each to its owning user."""
    if not findings:
        return

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            usernames = {f['owner_username'] for f in findings if f.get('owner_username')}
            owner_ids = {}
            if usernames:
                cur.execute(
                    "SELECT id, username FROM users WHERE username = ANY(%s)",
                    (list(usernames),)
                )
                owner_ids = {username: user_id for user_id, username in cur.fetchall()}

            values = [
                (
                    f['repo'],
                    f['scanner'],
                    f['severity'],
                    f['cve_id'],
                    f['package'],
                    f['file_path'],
                    f['line_number'],
                    f['description'],
                    f['fix_version'],
                    owner_ids.get(f.get('owner_username')),
                )
                for f in findings
            ]

            execute_values(
                cur,
                """
                INSERT INTO findings
                    (repo, scanner, severity, cve_id, package, file_path,
                     line_number, description, fix_version, owner_user_id)
                VALUES %s
                """,
                values
            )
            conn.commit()
            logger.info(f"Inserted {len(findings)} findings")
    except Exception as e:
        logger.error(f"Failed to insert findings: {e}")
        conn.rollback()
    finally:
        conn.close()


def move_to_processed(filepath: str):
    """Move processed file to processed directory."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    dest = os.path.join(PROCESSED_DIR, os.path.basename(filepath))
    os.rename(filepath, dest)
    logger.info(f"Moved {filepath} to {dest}")


def main():
    """Main loop - watch for new scan results and process them."""
    logger.info("Starting PipelineGuard Result Normalizer")
    logger.info(f"Watching directory: {RESULTS_DIR}")
    logger.info(f"Poll interval: {POLL_INTERVAL}s")

    # Wait for database to be ready
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

    # Main processing loop
    while True:
        try:
            # Find all JSON files in results directory
            pattern = os.path.join(RESULTS_DIR, '*.json')
            files = glob.glob(pattern)

            for filepath in files:
                findings = process_file(filepath)
                if findings:
                    insert_findings(findings)
                move_to_processed(filepath)

        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
