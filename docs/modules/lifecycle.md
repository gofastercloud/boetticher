# Module lifecycle

`boetticher deploy` applies the complete resolved platform model. Module
commands use the same planner and composition result.

```text
boetticher module list
boetticher module show monitoring
boetticher module plan monitoring
boetticher module enable monitoring --dry-run
boetticher module disable monitoring --dry-run
```

Enable and disable changes require `--confirm` when they persist configuration.
Normal disable is non-destructive: active declarations stop, while the owned
guest and declared persistent data are retained and remain marked as owned.

`--purge --confirm` is the explicit destructive form. It is not available for
mandatory modules. A purge plan must identify the module-owned guest and
persistent data before removal.

`module list`, `module show`, and `module status` report desired module state
as `Enabled` or `Disabled`. Live readiness is established separately through
`verify`, `doctor`, and service-specific live checks. Disabled optional modules
are intentional, not failures.
