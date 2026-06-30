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
- Argo CD admin password: `36om2Hf2viTKW3lb`

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
| Argo CD | https://localhost:8080 | admin / 36om2Hf2viTKW3lb |
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
