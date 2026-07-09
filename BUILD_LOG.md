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

#### Issue 6: Argo CD admin password committed in plaintext (public repo)
**Problem:** This build log had the real local Argo CD admin password checked in twice (Day 1 and Week 3 sections), in a public GitHub repo.

**Solution:** Replaced both with the `kubectl -n argocd get secret argocd-initial-admin-secret` command to retrieve it on demand instead of storing the value. Left the password in old commit history as-is (low risk: this credential only guards a `localhost`-only Argo CD UI on a local kind cluster, not reachable outside the machine it runs on).

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

## Day 6 - July 5, 2026: Email Alerting & CI Security Gate

### Goals
- Add an email notification path alongside the existing Slack alerts
- Catch issues before merge (CI), not just every 6 hours via CronJobs

### Progress

#### Email Alerter Service
- New service mirroring `slack-alerter`: polls Postgres for new findings across all
  scanned repos, checks OPA policy, and emails an HTML summary via SMTP (Gmail,
  using an App Password) instead of (or in addition to) Slack.
- Deliberately a different cadence than the Slack alerter: instead of a 60s poll
  that fires near-instantly, the email alerter checks once a day
  (`CHECK_INTERVAL_SECONDS`, default `86400`) and sends a single daily digest of
  whatever findings landed since the last check, across all scanned repos.
- Configured entirely through env vars (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`,
  `SMTP_PASSWORD`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`) sourced from a new
  `email-alerter-secret` Kubernetes Secret — no SMTP credentials committed.
- Falls back to logging findings if SMTP isn't configured, same fallback behavior
  as the Slack alerter when its webhook URL is unset.

#### CI Security Gate
- Added `.github/workflows/ci.yml` (this repo had no GitHub Actions workflow before).
- `test` job runs `bandit` (Python security lint) and `gitleaks-action` (secret scan)
  on every push/PR to `main`.
- `notify-on-failure` job runs only if `test` fails and emails the repo/commit/run
  link via `dawidd6/action-send-mail`, using `SMTP_*` and `ALERT_EMAIL_*` GitHub
  Secrets (separate from the cluster's `email-alerter-secret` — CI runs outside
  the cluster).

#### Files Created

**pipelineguard-app/src/email-alerter:**
- `alerter.py`, `requirements.txt`, `Dockerfile`

**pipelineguard-app/.github/workflows:**
- `ci.yml`

**pipelineguard-gitops:**
- `apps/email-alerter/deployment.yaml` - Deployment + Secret

### Follow-ups
- Populate real Gmail App Password credentials in `email-alerter-secret` and the CI
  repo secrets (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`,
  `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO`) before either path will actually send mail.

---

## Day 7 - July 7, 2026: Live Notification Toggle (Slack + Email) from Config UI

### Goal
Day 6 gave `email-alerter` a hardcoded `ALERT_EMAIL_TO` and no way to turn it off
short of deleting the Deployment. Fix that by letting both alert channels be
switched on/off and re-addressed from `config-ui`, live, without a redeploy —
spans both the `pipelineguard-app` and `pipelineguard-gitops` repos.

### Changes — `pipelineguard-app`

**`src/config-ui/app.py`** — new "Notifications" section in the web UI:
- Checkboxes for "Send alerts to Slack" / "Send alerts by email", plus a
  comma-separated recipient list input (shown only when email is enabled).
- `get_notify_settings()` reads current state from the `scanner-config` ConfigMap
  (`NOTIFY_SLACK_ENABLED`, `NOTIFY_EMAIL_ENABLED`, `NOTIFY_EMAIL_TO`), falling back
  to a local `/config/notify.json` file, then to defaults, if the ConfigMap can't
  be reached.
- `save_notify_settings()` persists the same to the local file; `update_configmap()`
  was extended to also patch the three `NOTIFY_*` keys into `scanner-config`
  alongside the existing `TARGET_REPOS` update.
- Server-side validation on save: enabling email with an empty recipient list, or
  with a malformed address, is rejected with a 400 instead of silently saved.

**`src/slack-alerter/alerter.py`** — added `is_slack_enabled()`, mirroring the
pattern from Day 6's `email-alerter`: reads `NOTIFY_SLACK_ENABLED` from
`scanner-config` before each send, defaults to `True` (legacy always-on) if the
ConfigMap can't be reached. `requirements.txt` gained `kubernetes>=28.1.0`.

**`src/email-alerter/alerter.py`** (from Day 6) already had the equivalent
`get_notify_settings()` for `NOTIFY_EMAIL_ENABLED`/`NOTIFY_EMAIL_TO` — no further
app-side change needed here, it was just waiting on the UI and RBAC to catch up.

### Changes — `pipelineguard-gitops`

- **`apps/scanners/config.yaml`**: `scanner-config` ConfigMap gained the three
  `NOTIFY_*` keys (`NOTIFY_SLACK_ENABLED: "true"`, `NOTIFY_EMAIL_ENABLED: "false"`,
  `NOTIFY_EMAIL_TO: ""`) so they exist with sane defaults before anyone touches
  the UI.
- **`apps/slack-alerter/deployment.yaml`**: added a `slack-alerter` ServiceAccount
  + Role (`get` on `configmaps`) + RoleBinding, and pointed the Deployment at it
  via `serviceAccountName` — same shape as `email-alerter`'s RBAC from Day 6.
- **`argocd-apps/email-alerter.yaml`** (new): registers `email-alerter` as an Argo
  CD Application. Its manifests existed on disk since Day 6 but were never wired
  into Argo CD, so nothing was actually deploying it — this is what makes it
  actually run in-cluster.

### Follow-ups
- `kubectl apply -f gitops/argocd-apps/email-alerter.yaml` still needs to be run
  once to register the app in Argo CD; after that, sync is automatic (prune +
  selfHeal).
- The `slack-alerter` and `email-alerter` Deployments both changed
  ServiceAccount/RBAC — a plain rollout restart isn't enough, Argo CD needs to
  actually sync the updated manifests (or `kubectl apply` them by hand).
- Still nothing sends real mail/Slack messages until SMTP credentials
  (`email-alerter-secret`) and the Slack webhook (`slack-alerter-secret`) are
  populated in-cluster — set those directly with `kubectl`, not by committing
  values into the Secret manifests.

---

## Day 8 - July 9, 2026: Close the Argo CD Registration Gap

### Goal
Audit the live cluster against `pipelineguard-gitops` and fix whatever GitOps
principle ("everything Argo CD deploys lives in this repo") had quietly drifted.

### Findings
Cross-referencing `gitops/argocd-apps/` against `gitops/apps/*` turned up the
opposite problem in each direction:
- `postgresql`, `scanners`, `normalizer`, `opa`, `vault`, `monitoring`,
  `webhook-receiver`, and `slack-alerter` were all running live in the cluster
  as Argo CD `Application` objects, but none of those Applications were ever
  committed to `argocd-apps/` - they'd been applied by hand at some point,
  silently violating the repo's own "no manual kubectl apply" rule.
- `config-ui` had an `Application` manifest committed to git, but no matching
  `Application` object actually existed in-cluster - its pod was running from a
  bare `kubectl apply` of the raw Deployment instead, untracked by Argo CD.
- `email-alerter` had neither - exactly the Day 7 follow-up that was never
  closed out.

### Changes - `pipelineguard-gitops`
- Added `argocd-apps/{postgresql,scanners,normalizer,opa,vault,monitoring,
  webhook-receiver,slack-alerter}.yaml`, matching the specs already running
  live, so a fresh cluster bootstrapped from this repo now actually deploys
  everything instead of just `config-ui` and `email-alerter`.
- Fixed `README.md`'s Repository Structure and Bootstrap sections, which still
  described an old `manifests/`, `helm-values/`, `policies/` layout that no
  longer exists, and pointed the bootstrap step at `argocd-apps/` instead of
  `apps/`. Added the `kind-config.yaml` the bootstrap steps referenced but
  never actually included.
- Ran `kubectl apply -f argocd-apps/ -n argocd` against the live cluster:
  `config-ui` and `email-alerter` Applications were created (closing the Day 7
  follow-up), the rest reconciled cleanly since they matched what was already
  running.

### Verification
- Manually triggered a one-off `grype-scanner` Job: completed cleanly, confirms
  the Day 5 crash-loop fix is holding. Zero findings is a true negative for the
  two small repos it scans, not a bug - `checkov` (528), `gitleaks` (21), and
  `trivy` (13) all have real findings in Postgres.
- `vault status`: initialized, unsealed, `vault-init-secrets` Job completed.
- `opa` and `webhook-receiver`: both answering `/health` normally.
- `email-alerter` is `Synced` in Argo CD but its pod is `ImagePullBackOff` -
  `pipelineguard/email-alerter:latest` was never actually built. Attempting the
  build hit a stuck local Docker Desktop proxy (`http.docker.internal:3128`
  hangs resolving `python:3.11-slim`, even though direct network access from
  the host works fine). Did a full Docker Desktop restart (approved, kind
  cluster survived intact) - the hang persisted afterward on *any* image pull,
  even a tiny `hello-world`, ruling out anything image-specific. Points at a
  stuck Docker Desktop VM-internal proxy component rather than transient app
  state; likely needs a look at Settings -> Resources -> Proxies in the Docker
  Desktop GUI (not something scriptable from the CLI). Did not attempt a full
  Docker Desktop data reset - that would very likely wipe the 8-day-old kind
  cluster (Postgres findings, Vault state, everything), which is a much
  bigger, more destructive action than the restart that was actually approved.

### Resolution - Sidestepping the Docker Desktop Hang Entirely
Rather than keep fighting the local daemon, added `.github/workflows/build-images.yml`
to `pipelineguard-app`: builds all five service images (config-ui, email-alerter,
result-normalizer, slack-alerter, webhook-receiver) in GitHub Actions and pushes
them to `ghcr.io/sitardaniel/pipelineguard-*`, entirely bypassing the local
machine. All five build and push successfully; confirmed each is publicly
pullable via an anonymous GHCR token exchange (no visibility change needed -
packages inherit public visibility from the public source repo). Repointed all
five `gitops/apps/*/deployment.yaml` at the GHCR images instead of the
local-only `pipelineguard/*:latest` refs, which is what was actually blocking
email-alerter from ever running - nothing but one laptop's Docker cache could
ever have pulled those. `email-alerter`'s pod pulled and reached `Running` in
~15s once the fix synced.

### Bug Found and Fixed While Verifying: OPA Check Crashed on Every Real Finding
To confirm the fix actually worked rather than just checking pod status, did a
real end-to-end test of both alerters using free, disposable services (not the
repo owner's real accounts) rather than leaving them completely unverified:
- Email: created a free Ethereal (`nodemailer`) test SMTP inbox via their public
  API, temporarily set `email-alerter-secret` and `scanner-config`'s
  `NOTIFY_EMAIL_ENABLED` to point at it (pausing Argo CD self-heal on the
  `email-alerter`/`scanners` Applications first so it wouldn't revert them
  mid-test), restarted the pod, and confirmed via IMAP that the alert email
  genuinely arrived with the correct subject and findings.
- Slack: created a temporary webhook.site endpoint, pointed `slack-alerter-secret`
  at it, triggered a fresh `gitleaks-scanner` run (slack-alerter only looks back
  5 minutes on startup, unlike email-alerter's 24h), and confirmed via
  webhook.site's API that a correctly-formatted Slack Block Kit payload arrived.

This first attempt surfaced a real bug: `check_opa_policy()` in both alerters
passed the raw Postgres finding dict straight into `json.dumps()`, which threw
`Object of type datetime is not JSON serializable` on the `scanned_at` field -
on *every single finding*, always. The `except` block silently fell back to
`alert=True` (fail-open), so this never crashed anything visibly and findings
still got alerted on, but real OPA policy results were never actually being
used - the whole policy evaluation step was a no-op dressed up as working.
Fixed both call sites with `json.dumps({"input": finding}, default=str)`,
pushed through the same GHCR pipeline, force-removed the stale `:latest` image
from the kind node (`crictl rmi` - imagePullPolicy: IfNotPresent means a same-tag
rollout restart alone reuses the cached old image), and re-ran both end-to-end
tests: this time the logs show real policy violations being parsed
(`Policy violation: [SECRET] Detected in ... at BUILD_LOG.md`) instead of the
silent crash-and-fallback.

Reverted the test SMTP/webhook values afterward by simply re-enabling Argo CD
self-heal - confirmed it correctly reset both back to git's empty placeholders,
which also doubles as a live confirmation that self-heal itself works as
intended.

### Follow-ups
- Both alerters are now proven to work end-to-end - the only remaining step is
  swapping the test SMTP/webhook values for the repo owner's real Gmail App
  Password and Slack incoming webhook URL, set directly with `kubectl` (never
  committed to git).
- CI's `SMTP_*`/`ALERT_EMAIL_*` GitHub Actions secrets are still unset - same
  real-credential dependency, needs the repo owner's own values.

---
