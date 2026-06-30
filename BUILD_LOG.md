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
