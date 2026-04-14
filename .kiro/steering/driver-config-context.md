---
inclusion: fileMatch
fileMatchPattern: "driver/config/**,driver/registry_sql.go,driver/registry.go,driver/di.go"
---

# Driver & Configuration Context

When working on driver/config code, follow these patterns.

## Config Key Pattern

All config keys are `Key*` constants in `driver/config/provider.go`:
```go
const KeyAccessTokenLifespan = "ttl.access_token"
```

Each key has a getter method on `DefaultProvider`:
```go
func (p *DefaultProvider) AccessTokenLifespan(ctx context.Context) time.Duration {
    return p.getProvider(ctx).DurationF(KeyAccessTokenLifespan, time.Hour)
}
```

Always accept `ctx context.Context` as first parameter (multi-tenant config support).

## Provider Interface Pattern

Each feature defines a provider interface in `fosite/config.go`:
```go
type DPoPConfigProvider interface {
    GetDPoPEnabled(ctx context.Context) bool
    GetDPoPSigningAlgValuesSupported(ctx context.Context) []string
}
```

The interface is embedded in `Configurator` (`fosite/fosite.go`) and implemented on `fositex.Config` or `DefaultProvider`.

## Registry Pattern

`driver/registry_sql.go` → `RegistrySQL` is the single concrete DI container. Uses lazy initialization:
```go
func (m *RegistrySQL) Writer() herodot.Writer {
    if m.writer == nil {
        m.writer = herodot.NewJSONWriter(m.Logger())
    }
    return m.writer
}
```

New storage accessors and factory registrations go here. Use `ExtraFositeFactories()` for OIDC4VCI handler registration, gated by config flags.

## OIDC4VCI Config Keys (New)

When adding OIDC4VCI config keys, follow the naming pattern:
- `KeyPreAuthorizedCodeEnabled`, `KeyDPoPEnabled`, `KeyRAREnabled`, `KeyHAIPEnforced`, `KeyWalletAttestationEnabled`, `KeyAuthResponseIssParameterEnabled`
- Group related keys together with comments

## Key References

- #[[file:docs/ai-context/01-hydra-internal-design.md]] — Registry pattern, Configurator interface
- #[[file:docs/ai-context/04-fork-maintenance-strategy.md]] — Fork maintenance, config key strategy
