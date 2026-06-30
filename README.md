# 🛡️ PipelineGuard - App

> Automated security scanning platform for GitHub repositories. Runs parallel vulnerability scans on every push and surfaces findings in a centralized dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security: Trivy](https://img.shields.io/badge/scanner-Trivy-blue)](https://github.com/aquasecurity/trivy)
[![Security: Gitleaks](https://img.shields.io/badge/scanner-Gitleaks-red)](https://github.com/gitleaks/gitleaks)
[![Security: Grype](https://img.shields.io/badge/scanner-Grype-orange)](https://github.com/anchore/grype)
[![Security: Checkov](https://img.shields.io/badge/scanner-Checkov-green)](https://github.com/bridgecrewio/checkov)

---

## What This Repo Contains

This is the **application layer** of PipelineGuard. It holds:

- Scanner runner logic (orchestrates Trivy, Checkov, Gitleaks, Grype)
- Result normalizer (converts scanner output to a unified schema)
- Webhook receiver (listens for GitHub push events)
- Dockerfiles for all components
- PostgreSQL schema definitions

The **GitOps config** (Kubernetes manifests, Argo CD apps) lives in [`pipelineguard-gitops`](https://github.com/sitardaniel/pipelineguard-gitops).  
The **infrastructure** (Terraform/Terragrunt for AWS) lives in [`pipelineguard-infra`](https://github.com/sitardaniel/pipelineguard-infra).

---

## Architecture Overview

```
GitHub Push / CronJob
        │
        ▼
  Webhook Receiver
        │
        ▼
   Argo CD (GitOps)
        │
   ┌────┴────┐
   ▼         ▼
Scan Jobs   CronJob
(parallel)
  │  Trivy
  │  Checkov
  │  Gitleaks
  │  Grype
        │
        ▼
  Result Normalizer
        │
        ▼
   PostgreSQL ──► Grafana Dashboard
                       │
                  OPA Policies
                       │
                  Slack Alerts
```

---

## Scanners

| Scanner  | What It Catches                              |
|----------|----------------------------------------------|
| Trivy    | Container image CVEs, IaC misconfigurations  |
| Checkov  | Terraform/IaC policy violations              |
| Gitleaks | Secrets and credentials in Git history       |
| Grype    | Vulnerable dependencies in package manifests |

---

## Local Development (Phase 1 - kind cluster)

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/)
- [Helm](https://helm.sh/docs/intro/install/)
- [Argo CD CLI](https://argo-cd.readthedocs.io/en/stable/cli_installation/)

### Quickstart

```bash
# 1. Clone all three repos
git clone https://github.com/sitardaniel/pipelineguard-app
git clone https://github.com/sitardaniel/pipelineguard-gitops
git clone https://github.com/sitardaniel/pipelineguard-infra

# 2. Create local kind cluster
kind create cluster --name pipelineguard

# 3. Follow setup in pipelineguard-gitops README to bootstrap Argo CD
```

---

## Repository Structure

```
pipelineguard-app/
├── scanners/
│   ├── trivy/          # Trivy runner + Dockerfile
│   ├── checkov/        # Checkov runner + Dockerfile
│   ├── gitleaks/       # Gitleaks runner + Dockerfile
│   └── grype/          # Grype runner + Dockerfile
├── normalizer/         # Result normalization service
├── webhook-receiver/   # GitHub webhook listener
├── db/
│   └── schema.sql      # PostgreSQL schema
├── .github/
│   ├── workflows/      # CI pipelines
│   └── ISSUE_TEMPLATE/
├── SECURITY.md
└── README.md
```

---

## Security

Please read [SECURITY.md](SECURITY.md) before reporting vulnerabilities.

---

## License

MIT © [sitardaniel](https://github.com/sitardaniel)
