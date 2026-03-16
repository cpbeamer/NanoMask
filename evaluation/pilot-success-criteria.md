# Pilot Success Criteria

Agree on these metrics before pilot start so expansion is tied to evidence, not opinion.

| Area | Target | Evidence |
|---|---|---|
| Detection coverage | 95%+ of seeded PII/PHI test values detected in agreed workflows | report-only logs, audit events, sample replay |
| False positive rate | <2% on buyer-approved evaluation corpus | redaction review worksheet |
| Latency overhead | within buyer-approved SLO for proxied routes | local benchmark plus pilot traffic measurement |
| Deployment time | first environment live in 1 business day or less | onboarding runbook timestamps |
| Compatibility | no auth, header, or SSE regressions in target workflows | compatibility suite plus pilot smoke tests |
| Security review readiness | security packet accepted for initial review without blocker gaps | buyer security questionnaire and meeting notes |
| Expansion trigger | sidecar or gateway rollout justified by measured coverage and operator fit | signed pilot closeout |
