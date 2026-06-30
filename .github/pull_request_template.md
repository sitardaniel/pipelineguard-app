## Summary

<!-- What does this PR do? One paragraph max. -->

## Type of Change

- [ ] Bug fix
- [ ] New feature / scanner
- [ ] Refactor
- [ ] Documentation
- [ ] CI/CD change
- [ ] Security fix

## Security Checklist

- [ ] No secrets, tokens, or credentials added to any file
- [ ] No hardcoded IPs, hostnames, or internal paths
- [ ] New Docker images are scanned with Trivy locally before opening this PR
- [ ] Environment variables are documented in `.env.example` if added
- [ ] Vault paths are used for any new secrets (not Kubernetes Secrets directly)

## Testing

<!-- How was this tested? Local kind cluster? Unit tests? -->

- [ ] Tested locally on kind cluster
- [ ] Unit tests pass (`pytest` / `go test`)
- [ ] Scanner output validated against normalizer schema

## Related Issues

Closes #
