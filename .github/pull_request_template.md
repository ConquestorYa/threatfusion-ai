## Summary

- What changed?
- Why was it needed?

## Validation

- [ ] `python -m pytest`
- [ ] `python -m ruff check .`
- [ ] No secrets or local snapshot data were committed
- [ ] Documentation was updated when behavior or architecture changed

## ML / security checks (when relevant)

- [ ] No train/test leakage was introduced
- [ ] Threat indicators remain inert data; no IOC URLs/domains are visited or resolved
- [ ] API keys/tokens are not stored in source, tests, logs, or metadata
- [ ] Results are reproducible where applicable
