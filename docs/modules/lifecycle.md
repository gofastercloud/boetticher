# Module lifecycle

`boetticher deploy` applies the complete resolved platform model. Preview
module changes with `--dry-run`. `configure` changes site configuration but
does not deploy. `enable` and `disable` apply immediately with `--confirm`.
Disabling keeps the owned guest and persistent data; `--purge --confirm` is the
destructive option.

```text
boetticher module list
boetticher module show monitoring
boetticher module plan monitoring
boetticher module enable monitoring --dry-run
boetticher module disable monitoring --dry-run

boetticher module show tailnet-router
boetticher module plan tailnet-router
boetticher module status bifrost
boetticher module secrets bifrost list
boetticher module secrets bifrost set openrouter_api_key
```

Enable and disable changes require `--confirm` when they persist configuration.
Normal disable is non-destructive: active declarations stop, while the owned
guest and declared persistent data are retained and remain marked as owned.
The retained guest's module services are stopped and disabled by the same
deployment convergence through the authenticated Proxmox guest-execution
boundary, so retained resources remain inactive across reboot even when the
guest network is correctly isolated from the Proxmox management zone.

`--purge --confirm` is the explicit destructive form. It is not available for
mandatory modules. A purge plan must reconstruct the disabled module's
declaration in memory, resolve its qualified artifact, and identify the exact
module-owned guest, attached volumes, and persistent data before removal.

`module list`, `module show`, and `module status` report desired module state
as `Enabled` or `Disabled`. A named module status also reports non-secret
configuration and the presence of declared secrets; runtime readiness is
established separately through `verify`, `doctor`, and service-specific live
checks. A requested runtime check that cannot establish success fails with a
next action. Disabled optional modules are intentional and are not asserted
as unhealthy.
