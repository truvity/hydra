---
inclusion: fileMatch
fileMatchPattern: "fosite/authorize_write.go,fosite/authorize_error.go,fosite/authorize_request_handler.go,fosite/client_authentication.go"
---

# Fork Maintenance — Upstream-Touching Files

These files exist upstream and are modified by OIDC4VCI features. Handle with care.

## Conflict Risk Files

| File | Risk | OIDC4VCI Change |
|------|------|-----------------|
| `fosite/fosite.go` | Medium | Embed new provider interfaces in `Configurator` |
| `fosite/config.go` | Low-Medium | Define new provider interfaces (append at end) |
| `fosite/authorize_write.go` | Medium | Add RFC 9207 `iss` parameter to success responses |
| `fosite/authorize_error.go` | Medium | Add RFC 9207 `iss` parameter to error responses |
| `fosite/authorize_request_handler.go` | Low | HAIP PAR enforcement check |
| `flow/consent_types.go` | Medium | Add `AuthorizationDetails`, `IssuerState` fields |
| `oauth2/handler.go` | High | Metadata struct fields + population logic |

## Rules

1. Add new struct fields at the END of structs, before closing brace
2. Add new interface embeddings at the END of interface composition
3. Mark all additions with `// OIDC4VCI extension` comments
4. Keep changes minimal — prefer additive over modifying existing lines
5. When upstream rebases conflict, keep upstream changes first, re-apply our additions

## Key References

- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Full fork maintenance strategy
