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
