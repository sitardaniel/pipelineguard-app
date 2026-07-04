# PipelineGuard - Build Log

A daily progress journal documenting the build process, issues encountered, and solutions.

---

## Day 1 - June 30, 2026

### Goals
- Set up local kind cluster
- Install Argo CD
- Connect Argo CD to pipelineguard-gitops repo
- Deploy hello-world app to confirm GitOps loop works

### Progress

#### Prerequisites Check
- kind v0.31.0 - installed
- kubectl v1.34.2 - installed
- Docker Desktop - started
- argocd CLI v3.4.4 - installed via Homebrew

#### Tasks Completed
- [x] Kind cluster created (`kind-pipelineguard`)
- [x] Argo CD installed (namespace: `argocd`)
- [x] Argo CD connected to gitops repo
- [x] Hello-world app deployed via GitOps

#### Cluster Details
- Cluster name: `pipelineguard`
- Kubernetes version: v1.35.0
- Context: `kind-pipelineguard`
- Argo CD UI: https://localhost:8080
- Argo CD admin password: retrieve with `kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d`

### Issues & Solutions

#### Issue 1: Argo CD CRD too large
**Problem:** When installing Argo CD, the `applicationsets.argoproj.io` CRD failed with error:
```
metadata.annotations: Too long: may not be more than 262144 bytes
```

**Solution:** Used server-side apply instead of client-side apply:
```bash
kubectl apply -n argocd -f <manifest-url> --server-side=true --force-conflicts
```

---

### Terraform & Terragrunt Setup

#### Tools Installed
- Terraform v1.15.5 - already installed
- Terragrunt v1.0.8 - installed via Homebrew

#### Modules Created (in pipelineguard-infra)

| Module | Purpose |
|--------|---------|
| `modules/vpc` | VPC with public/private subnets, NAT gateway, route tables |
| `modules/eks` | EKS cluster, managed node group, IRSA (IAM Roles for Service Accounts) |
| `modules/rds` | PostgreSQL RDS instance with security groups |
| `modules/ecr` | ECR repositories for scanner container images |
| `modules/s3` | S3 bucket for Terraform state + DynamoDB lock table |

#### Terragrunt Configuration

```
pipelineguard-infra/
├── terragrunt.hcl              # Root config (remote state, provider)
├── environments/
│   ├── dev/
│   │   ├── vpc/terragrunt.hcl
│   │   ├── eks/terragrunt.hcl
│   │   ├── rds/terragrunt.hcl
│   │   └── ecr/terragrunt.hcl
│   └── prod/
│       ├── vpc/terragrunt.hcl
│       ├── eks/terragrunt.hcl
│       ├── rds/terragrunt.hcl
│       └── ecr/terragrunt.hcl
└── modules/
    ├── vpc/
    ├── eks/
    ├── rds/
    ├── ecr/
    └── s3/
```

#### Environment Differences

| Setting | Dev | Prod |
|---------|-----|------|
| EKS nodes | t3.medium SPOT | t3.large ON_DEMAND |
| Node count | 2 (1-4) | 3 (2-6) |
| RDS instance | db.t3.micro | db.t3.small |
| RDS Multi-AZ | No | Yes |
| VPC CIDR | 10.0.0.0/16 | 10.1.0.0/16 |

#### Validation
All 5 Terraform modules validated successfully with `terraform validate`.

---

## Week 1 Progress Summary

| Task | Status |
|------|--------|
| Set up kind cluster locally | Done |
| Install Argo CD and connect to gitops repo | Done |
| Deploy hello-world app via GitOps | Done |
| Write Terraform module for EKS | Done |
| Configure Terragrunt root with S3 backend | Done |

**Week 1 complete!**

---

## Day 1 (continued) - Week 2: Scanning Pipeline

### Goals
- Build scanner Job manifests (Trivy, Checkov, Gitleaks, Grype)
- Deploy PostgreSQL for storing findings
- Write result normalizer service
- Test the complete scan pipeline

### Progress

#### PostgreSQL Deployed
- Deployed via Argo CD as GitOps application
- Schema includes `findings` table with indexes
- Views for `critical_findings` and `findings_summary`

#### Scanner CronJobs Created

| Scanner | Purpose | Schedule |
|---------|---------|----------|
| Trivy | Container/IaC vulnerabilities | Every 6 hours |
| Checkov | Terraform misconfigurations | Every 6 hours (+15m) |
| Gitleaks | Secret detection in git history | Every 6 hours (+30m) |
| Grype | Dependency vulnerabilities | Every 6 hours (+45m) |

Each scanner:
- Uses init container to clone repos
- Outputs JSON results to shared PVC
- Runs as Kubernetes CronJob

#### Result Normalizer Service
- Python service watching `/results` directory
- Normalizes output from all 4 scanners to common schema
- Inserts findings into PostgreSQL
- Built as container, loaded into kind cluster

#### Test Results

First scan results after running Trivy and Checkov:

```
 scanner | severity | count
---------+----------+-------
 checkov | MEDIUM   |    32
 trivy   | CRITICAL |     4
 trivy   | HIGH     |     3
 trivy   | MEDIUM   |     6
```

**45 total findings detected!**

### Argo CD Applications

| App | Path | Status |
|-----|------|--------|
| hello-world | apps/hello-world | Healthy |
| postgresql | apps/postgresql | Healthy |
| scanners | apps/scanners | Healthy |
| normalizer | apps/normalizer | Healthy |

### Files Created

**pipelineguard-app:**
- `src/normalizer/normalizer.py` - Main normalizer logic
- `src/normalizer/requirements.txt` - Python dependencies
- `src/normalizer/Dockerfile` - Container build

**pipelineguard-gitops:**
- `apps/postgresql/deployment.yaml` - PostgreSQL + PVC
- `apps/postgresql/init-schema.yaml` - Schema init Job
- `apps/scanners/config.yaml` - Scanner config + shared PVC
- `apps/scanners/trivy-job.yaml` - Trivy CronJob
- `apps/scanners/checkov-job.yaml` - Checkov CronJob
- `apps/scanners/gitleaks-job.yaml` - Gitleaks CronJob
- `apps/scanners/grype-job.yaml` - Grype CronJob
- `apps/normalizer/deployment.yaml` - Normalizer Deployment

---

## Week 2 Progress Summary

| Task | Status |
|------|--------|
| Build Trivy scanner Job | Done |
| Add Checkov, Gitleaks, Grype Jobs | Done |
| Write result normalizer service | Done |
| Deploy PostgreSQL in cluster | Done |
| Verify findings written to DB | Done (45 findings) |

**Week 2 scanning pipeline complete!**

---

## Day 1 (continued) - Week 3: Observability

### Goals
- Deploy Prometheus + Grafana via Helm
- Build findings Grafana dashboard
- Deploy Vault for secrets management
- Wire up OPA policy evaluation

### Progress

#### Prometheus + Grafana Stack
- Deployed kube-prometheus-stack via Helm chart in Argo CD
- Includes: Prometheus, Grafana, Node Exporter, kube-state-metrics
- PostgreSQL datasource configured for findings queries
- Pushgateway enabled for scanner job metrics
- **Access:** http://localhost:3000 (admin/pipelineguard)

#### Grafana Dashboard Created
Custom "PipelineGuard - Security Findings" dashboard with:
- Stat panels: Critical, High, Medium counts
- Pie charts: Findings by Severity, by Scanner
- Table: Recent Critical & High findings
- Bar chart: Open findings by repository

#### Vault Deployed
- HashiCorp Vault in dev mode for local development
- Root token: `root`
- Secrets initialized:
  - `secret/pipelineguard/database` - PostgreSQL credentials
  - `secret/pipelineguard/github` - GitHub token placeholder
  - `secret/pipelineguard/slack` - Slack webhook placeholder
  - `secret/pipelineguard/webhook` - HMAC secret for webhook validation

#### OPA Policy Engine
- Open Policy Agent deployed with Rego policy
- Policy evaluates findings and generates alerts
- Test result for critical finding:
```json
{
  "result": {
    "alert": true,
    "allow": false,
    "violation": ["[CRITICAL] CVE-2024-1234 in pipelineguard-app - libssl"]
  }
}
```

### Issues & Solutions

#### Issue 2: OPA Rego syntax changes
**Problem:** Newer OPA versions require `if` keyword before rule bodies and `contains` for partial set rules.

**Solution:** Updated Rego policy to v1 syntax:
```rego
import rego.v1
allow if { ... }
violation contains msg if { ... }
```

#### Issue 3: OPA loading duplicate policies
**Problem:** ConfigMap mounting created symlinks that OPA loaded multiple times.

**Solution:** Used `subPath` to mount only the specific policy file:
```yaml
volumeMounts:
- name: policy
  mountPath: /policies/policy.rego
  subPath: policy.rego
```

### Argo CD Applications (Updated)

| App | Namespace | Status |
|-----|-----------|--------|
| hello-world | default | Healthy |
| postgresql | pipelineguard | Healthy |
| scanners | pipelineguard | Healthy |
| normalizer | pipelineguard | Healthy |
| kube-prometheus-stack | monitoring | Healthy |
| vault | vault | Healthy |
| opa | pipelineguard | Healthy |

### Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Argo CD | https://localhost:8080 | admin / (see `kubectl -n argocd get secret argocd-initial-admin-secret`) |
| Grafana | http://localhost:3000 | admin / pipelineguard |
| Vault | http://localhost:8200 | token: root |

---

## Week 3 Progress Summary

| Task | Status |
|------|--------|
| Deploy Prometheus + Grafana via Helm | Done |
| Build findings Grafana dashboard | Done |
| Deploy Vault | Done |
| Wire up OPA policy evaluation | Done |

**Week 3 observability complete!**

---

## Day 1 (continued) - Week 4: Polish & Integration

### Goals
- Add GitHub webhook receiver service
- Set up Slack alerting for critical findings
- Update README with architecture diagram
- Document the complete setup

### Progress

#### Webhook Receiver Service
Created Python service that:
- Listens for GitHub webhook events
- Validates HMAC signatures
- Creates Kubernetes Jobs from scanner CronJobs on push to main/master
- RBAC configured for job creation permissions

#### Slack Alerter Service
Created Python service that:
- Polls PostgreSQL for new critical/high findings
- Integrates with OPA for policy-based alert decisions
- Sends formatted Slack messages with finding details
- Configurable severity thresholds

#### Services Built and Deployed
```bash
# Images built and loaded into kind
pipelineguard/webhook-receiver:latest
pipelineguard/slack-alerter:latest
```

### Files Created

**pipelineguard-app/src/webhook-receiver:**
- `main.py` - Webhook handler with HMAC validation
- `requirements.txt` - kubernetes client
- `Dockerfile`

**pipelineguard-app/src/slack-alerter:**
- `alerter.py` - Slack notification logic with OPA integration
- `requirements.txt` - psycopg2-binary
- `Dockerfile`

**pipelineguard-gitops:**
- `apps/webhook-receiver/deployment.yaml` - Deployment, Service, RBAC, Secret
- `apps/slack-alerter/deployment.yaml` - Deployment, Secret

### Final Argo CD Applications

| App | Namespace | Status |
|-----|-----------|--------|
| hello-world | default | Healthy |
| postgresql | pipelineguard | Healthy |
| scanners | pipelineguard | Healthy |
| normalizer | pipelineguard | Healthy |
| kube-prometheus-stack | monitoring | Healthy |
| vault | vault | Healthy |
| opa | pipelineguard | Healthy |
| webhook-receiver | pipelineguard | Healthy |
| slack-alerter | pipelineguard | Healthy |

### Running Pods

```
NAME                                 READY   STATUS
opa-66f9db8888-dmtdw                 1/1     Running
postgresql-5585f77cbc-mtl9h          1/1     Running
result-normalizer-57dbfdb75c-ffqvv   1/1     Running
slack-alerter-6c87d54fc5-xwdrd       1/1     Running
webhook-receiver-dd8459c4d-l6qgp     1/1     Running
```

---

## Week 4 Progress Summary

| Task | Status |
|------|--------|
| Add GitHub webhook receiver | Done |
| Set up Slack alerting | Done |
| Update README with architecture | Done |
| Document complete setup | Done |

**Week 4 polish complete!**

---

## Project Complete - Summary

### What We Built (in one day!)

1. **Week 1 - Foundation**
   - Kind cluster with Argo CD
   - Terraform modules for AWS (VPC, EKS, RDS, ECR, S3)
   - Terragrunt configuration for dev/prod environments

2. **Week 2 - Scanning Pipeline**
   - 4 scanner CronJobs (Trivy, Checkov, Gitleaks, Grype)
   - Result normalizer service
   - PostgreSQL with findings schema
   - **45 findings detected in first scan!**

3. **Week 3 - Observability**
   - Prometheus + Grafana stack
   - Custom security findings dashboard
   - HashiCorp Vault for secrets
   - OPA for policy-as-code

4. **Week 4 - Integration**
   - GitHub webhook receiver
   - Slack alerter with OPA integration
   - Complete documentation

### Technologies Used

| Category | Tools |
|----------|-------|
| Container Orchestration | Kubernetes (kind), Argo CD |
| Infrastructure as Code | Terraform, Terragrunt |
| Security Scanning | Trivy, Checkov, Gitleaks, Grype |
| Observability | Prometheus, Grafana |
| Policy | Open Policy Agent (OPA) |
| Secrets | HashiCorp Vault |
| Database | PostgreSQL |

### Repository Links

- **App:** https://github.com/sitardaniel/pipelineguard-app
- **GitOps:** https://github.com/sitardaniel/pipelineguard-gitops
- **Infra:** https://github.com/sitardaniel/pipelineguard-infra

---

## Day 2 - July 5, 2026

### Goals
- Add UI for selecting which GitHub repos to scan

### Progress

#### Config UI Service
Created web UI that allows users to:
- Browse all GitHub repos for a user
- Search/filter repos by name or description
- Select which repos to include in scans
- Save selection to Kubernetes ConfigMap

#### Technical Details
- Python HTTP server with embedded HTML/CSS/JS
- Fetches repos from GitHub API (supports pagination)
- Updates `scanner-config` ConfigMap when saved
- RBAC configured for ConfigMap access
- Exposed via NodePort on port 30090

#### Files Created

**pipelineguard-app/src/config-ui:**
- `app.py` - Web server with GitHub API integration
- `requirements.txt` - kubernetes client
- `Dockerfile`

**pipelineguard-gitops:**
- `apps/config-ui/deployment.yaml` - Deployment, Service, RBAC, Secret
- `argocd-apps/config-ui.yaml` - Argo CD Application

### Access URLs (Updated)

| Service | URL | Credentials |
|---------|-----|-------------|
| Argo CD | https://localhost:8080 | admin / (see `kubectl -n argocd get secret argocd-initial-admin-secret`) |
| Grafana | http://localhost:3000 | admin / pipelineguard |
| Vault | http://localhost:8200 | token: root |
| Config UI | http://localhost:30090 | - |

---

## Day 5 - July 5, 2026: Grype Fix & IaC Security Hardening

### Issues & Solutions

#### Issue 4: Grype scanner crash-looping on every run
**Problem:** `grype-scanner` CronJob hit `RunContainerError` / `BackoffLimitExceeded` on every execution. `anchore/grype:latest` is a distroless image with no shell, so the manifest's `sh -c "..."` command could never start.

**Solution:** Switched to the `anchore/grype:debug` tag (ships a busybox shell) and called the binary via its full path `/grype`, since it isn't on `$PATH` even in the debug image.

#### Issue 5: 4 Critical findings in pipelineguard-infra (Trivy IaC scan)
**Problem:** Trivy's IaC scan flagged `modules/eks/main.tf` and `modules/rds/main.tf`:
- `AWS-0104` (x2): security groups allowed unrestricted egress (`0.0.0.0/0`, all ports)
- `AWS-0040` / `AWS-0041`: EKS cluster public endpoint open with no CIDR restriction

**Solution:** Scoped both security groups' egress to the VPC CIDR instead of `0.0.0.0/0`, and defaulted the EKS public endpoint to disabled (`endpoint_public_access = false`), with an explicit CIDR allowlist variable to opt back in per environment.

### Findings Snapshot (Postgres)

```
 scanner  | severity | count
----------+----------+-------
 checkov  | MEDIUM   |   320
 gitleaks | HIGH     |     9
 trivy    | CRITICAL |     4
 trivy    | HIGH     |     3
 trivy    | MEDIUM   |     6
```

---
