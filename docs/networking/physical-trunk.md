# Physical trunk

V1 can operate in virtual-only mode with no physical member on `vmbr1`. A second NIC and managed switch are recommended when physical TRUSTED, SANDBOX, or MGMT clients are needed.

Use `homelab network trunk status` to inspect the model. `attach` and `detach` are guarded, potentially locking live changes: they require explicit confirmation, must prove the interface is not the HOME/bootstrap interface, and must validate the recovery path before accepting the transition.
