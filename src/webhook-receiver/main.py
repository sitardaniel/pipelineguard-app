#!/usr/bin/env python3
"""
BaghGuard Webhook Receiver

Receives GitHub webhooks and triggers security scans.
Validates HMAC signatures and creates Kubernetes Jobs.
"""

import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

from kubernetes import client, config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('webhook-receiver')

# Configuration
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
NAMESPACE = os.getenv('NAMESPACE', 'baghguard')
PORT = int(os.getenv('PORT', '8080'))

# Scanner CronJob names to trigger
SCANNERS = ['trivy-scanner', 'checkov-scanner', 'gitleaks-scanner', 'grype-scanner']


def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook HMAC signature."""
    if not WEBHOOK_SECRET:
        logger.warning("No webhook secret configured, skipping verification")
        return True

    if not signature or not signature.startswith('sha256='):
        return False

    expected = 'sha256=' + hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)


def trigger_scan(repo_name: str, event_type: str):
    """Create Kubernetes Jobs from scanner CronJobs."""
    try:
        # Load in-cluster config
        config.load_incluster_config()
    except config.ConfigException:
        # Fall back to local kubeconfig for testing
        config.load_kube_config()

    batch_v1 = client.BatchV1Api()
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')

    triggered = []
    for scanner in SCANNERS:
        job_name = f"{scanner}-webhook-{timestamp}"[:63]  # K8s name limit

        try:
            # Get the CronJob to use as template
            cronjob = batch_v1.read_namespaced_cron_job(scanner, NAMESPACE)

            # Create Job from CronJob spec
            job = client.V1Job(
                api_version="batch/v1",
                kind="Job",
                metadata=client.V1ObjectMeta(
                    name=job_name,
                    namespace=NAMESPACE,
                    labels={
                        "app": scanner,
                        "triggered-by": "webhook",
                        "event-type": event_type,
                        "repo": repo_name[:63]
                    }
                ),
                spec=cronjob.spec.job_template.spec
            )

            batch_v1.create_namespaced_job(NAMESPACE, job)
            triggered.append(scanner)
            logger.info(f"Created job {job_name} for {scanner}")

        except client.ApiException as e:
            logger.error(f"Failed to create job for {scanner}: {e}")

    return triggered


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP handler for GitHub webhooks."""

    def do_POST(self):
        """Handle POST requests (webhooks)."""
        content_length = int(self.headers.get('Content-Length', 0))
        payload = self.rfile.read(content_length)

        # Verify signature
        signature = self.headers.get('X-Hub-Signature-256', '')
        if not verify_signature(payload, signature):
            logger.warning("Invalid webhook signature")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Invalid signature')
            return

        # Parse event
        event_type = self.headers.get('X-GitHub-Event', 'unknown')

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Invalid JSON')
            return

        # Extract repo info
        repo = data.get('repository', {})
        repo_name = repo.get('name', 'unknown')
        repo_full_name = repo.get('full_name', 'unknown')

        logger.info(f"Received {event_type} event for {repo_full_name}")

        # Only trigger scans for push events to main/master
        if event_type == 'push':
            ref = data.get('ref', '')
            if ref in ['refs/heads/main', 'refs/heads/master']:
                triggered = trigger_scan(repo_name, event_type)
                response = {
                    'status': 'ok',
                    'message': f'Triggered {len(triggered)} scanners',
                    'scanners': triggered
                }
            else:
                response = {
                    'status': 'skipped',
                    'message': f'Ignoring push to {ref}'
                }
        elif event_type == 'ping':
            response = {
                'status': 'ok',
                'message': 'Pong!'
            }
        else:
            response = {
                'status': 'skipped',
                'message': f'Ignoring event type: {event_type}'
            }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        """Health check endpoint."""
        if self.path == '/health' or self.path == '/healthz':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info("%s - %s", self.address_string(), format % args)


def main():
    """Start the webhook server."""
    logger.info(f"Starting webhook receiver on port {PORT}")
    logger.info(f"Webhook secret configured: {bool(WEBHOOK_SECRET)}")

    server = HTTPServer(('0.0.0.0', PORT), WebhookHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
