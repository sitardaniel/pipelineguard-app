# Security Policy

## Supported Versions

PipelineGuard is currently in active development. Security fixes are applied to the `main` branch only.

| Version | Supported |
|---------|-----------|
| main    | ✅        |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in PipelineGuard, please report it responsibly:

1. **Email**: Open a private GitHub Security Advisory using the [Security tab](../../security/advisories/new) of this repository.
2. **Include**:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fix (optional but appreciated)

You can expect:
- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Resolution or mitigation** within 30 days for critical issues

---

## Security Design Principles

PipelineGuard is built with the following security practices:

- **No secrets in Git** - All credentials are managed by HashiCorp Vault
- **Least privilege** - Kubernetes service accounts are scoped per component
- **Private by default** - Repos are private until explicitly made public
- **Secrets scanning enabled** - GitHub secret scanning and push protection are active on all repos
- **Dependabot alerts enabled** - Automated dependency vulnerability alerts
- **Branch protection** - `main` requires PR review; direct pushes are blocked
- **Image scanning** - All container images are scanned by Trivy before deployment

---

## Scope

This security policy applies to:
- `pipelineguard-app` (this repo)
- `pipelineguard-gitops`
- `pipelineguard-infra`

---

## Out of Scope

- Vulnerabilities in upstream tools (Trivy, Checkov, Gitleaks, Grype) - please report those to their respective maintainers
- Issues in third-party dependencies - report to the dependency maintainer; open a Dependabot PR here if a fix is available
