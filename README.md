# PipelineGuard - App

> Automated security scanning platform for GitHub repositories. Runs parallel vulnerability scans on every push and surfaces findings in a centralized dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Trivy](https://img.shields.io/badge/scanner-Trivy-blue)](https://github.com/aquasecurity/trivy)
[![Security: Gitleaks](https://img.shields.io/badge/scanner-Gitleaks-red)](https://github.com/gitleaks/gitleaks)
[![Security: Grype](https://img.shields.io/badge/scanner-Grype-orange)](https://github.com/anchore/grype)
[![Security: Checkov](https://img.shields.io/badge/scanner-Checkov-green)](https://github.com/bridgecrewio/checkov)

---

## What This Repo Contains

This is the **application layer** of PipelineGuard. It holds:

- **Result Normalizer** - Converts scanner output to unified schema, stores in PostgreSQL
- **Webhook Receiver** - Listens for GitHub push events, triggers scan jobs
- **Slack Alerter** - Monitors for critical findings, sends Slack notifications
- Dockerfiles for all components

Related repos:
- [`pipelineguard-gitops`](https://github.com/sitardaniel/pipelineguard-gitops) - Kubernetes manifests, Argo CD apps
- [`pipelineguard-infra`](https://github.com/sitardaniel/pipelineguard-infra) - Terraform/Terragrunt for AWS

---

## Architecture Overview

```
                              GitHub Push Event
                                     |
                                     v
                          +-------------------+
                          | Webhook Receiver  |
                          | (validates HMAC)  |
                          +--------+----------+
                                   |
                                   v
                          +-------------------+
                          |     Argo CD       |
                          |    (GitOps)       |
                          +--------+----------+
                                   |
             +---------------------+---------------------+
             |                     |                     |
             v                     v                     v
      +------------+        +------------+        +------------+
      |   Trivy    |        |  Checkov   |        |  Gitleaks  |
      | (CVEs/IaC) |        | (Terraform)|        | (Secrets)  |
      +-----+------+        +-----+------+        +-----+------+
             |                     |                     |
             +----------+----------+----------+----------+
                        |                     |
                        v                     v
                +---------------+      +------------+
                |    Grype      |      | Shared PVC |
                | (Dependencies)|      | /results   |
                +-------+-------+      +-----+------+
                        |                    |
                        +----------+---------+
                                   |
                                   v
                        +-------------------+
                        | Result Normalizer |
                        | (Python service)  |
                        +--------+----------+
                                 |
                 +---------------+---------------+
                 |                               |
                 v                               v
          +------------+                  +------------+
          | PostgreSQL |                  |    OPA     |
          | (findings) |                  | (policies) |
          +-----+------+                  +-----+------+
                |                               |
                v                               v
          +------------+                  +------------+
          |  Grafana   |                  |   Slack    |
          | Dashboard  |                  |  Alerter   |
          +------------+                  +------------+
```

---

## Components

### Scanners (Kubernetes CronJobs)

| Scanner | Purpose | Schedule |
|---------|---------|----------|
| Trivy | Container image CVEs, IaC misconfigurations | Every 6 hours |
| Checkov | Terraform/IaC policy violations | Every 6 hours (+15m) |
| Gitleaks | Secrets in Git history | Every 6 hours (+30m) |
| Grype | Vulnerable dependencies | Every 6 hours (+45m) |

### Services

| Service | Purpose |
|---------|---------|
| Result Normalizer | Watches scan output, normalizes to common schema, stores in PostgreSQL |
| Webhook Receiver | Validates GitHub webhooks (HMAC), triggers scanner jobs on push |
| Slack Alerter | Monitors for critical findings, sends formatted Slack alerts |

### Storage & Observability

| Component | Purpose |
|-----------|---------|
| PostgreSQL | Stores normalized findings with severity, CVE, package info |
| Grafana | Security findings dashboard with severity charts and tables |
| Prometheus | Cluster and scanner job metrics |
| Vault | Secrets management (dev mode for local) |
| OPA | Policy-as-code for alert decisions |

---

## Quick Start (Local Development)

### Prerequisites

- Docker Desktop
- [kind](https://kind.sigs.k8s.io/) v0.20+
- kubectl v1.28+
- [Argo CD CLI](https://argo-cd.readthedocs.io/en/stable/cli_installation/)

### Setup

```bash
# 1. Create kind cluster
kind create cluster --name pipelineguard

# 2. Install Argo CD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml --server-side

# 3. Get Argo CD admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# 4. Port forward Argo CD UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# 5. Build and load images
docker build -t pipelineguard/result-normalizer:latest src/normalizer/
docker build -t pipelineguard/webhook-receiver:latest src/webhook-receiver/
docker build -t pipelineguard/slack-alerter:latest src/slack-alerter/
kind load docker-image pipelineguard/result-normalizer:latest --name pipelineguard
kind load docker-image pipelineguard/webhook-receiver:latest --name pipelineguard
kind load docker-image pipelineguard/slack-alerter:latest --name pipelineguard

# 6. Deploy apps via Argo CD (see pipelineguard-gitops)
```

### Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Argo CD | https://localhost:8080 | admin / (see step 3) |
| Grafana | http://localhost:3000 | admin / pipelineguard |
| Vault | http://localhost:8200 | token: root |

---

## Repository Structure

```
pipelineguard-app/
├── src/
│   ├── normalizer/         # Result normalization service
│   │   ├── normalizer.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   ├── webhook-receiver/   # GitHub webhook listener
│   │   ├── main.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── slack-alerter/      # Slack notification service
│       ├── alerter.py
│       ├── requirements.txt
│       └── Dockerfile
├── BUILD_LOG.md            # Daily build progress journal
├── SECURITY.md
└── README.md
```

---

## Findings Schema

```sql
CREATE TABLE findings (
  id            UUID PRIMARY KEY,
  repo          TEXT NOT NULL,
  scanner       TEXT NOT NULL,      -- trivy, checkov, gitleaks, grype
  severity      TEXT NOT NULL,      -- CRITICAL, HIGH, MEDIUM, LOW
  cve_id        TEXT,
  package       TEXT,
  file_path     TEXT,
  line_number   INTEGER,
  description   TEXT,
  fix_version   TEXT,
  status        TEXT DEFAULT 'open', -- open, acknowledged, resolved
  scanned_at    TIMESTAMPTZ NOT NULL,
  resolved_at   TIMESTAMPTZ
);
```

---

## OPA Policy Example

```rego
package pipelineguard.policy

import rego.v1

# Alert on critical findings
alert if {
  input.severity == "CRITICAL"
  input.status == "open"
}

# Alert on any detected secret
alert if {
  input.scanner == "gitleaks"
  input.status == "open"
}

# Violation messages for Slack
violation contains msg if {
  input.severity == "CRITICAL"
  input.status == "open"
  msg := sprintf("[CRITICAL] %s in %s", [input.cve_id, input.repo])
}
```

---

## Production Deployment (AWS EKS)

See [`pipelineguard-infra`](https://github.com/sitardaniel/pipelineguard-infra) for Terraform/Terragrunt modules to deploy:

- VPC with public/private subnets
- EKS cluster with managed node groups
- RDS PostgreSQL
- ECR for container images

```bash
cd pipelineguard-infra/environments/dev
terragrunt run-all apply
```

---

## Security

Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

---

## License

MIT
