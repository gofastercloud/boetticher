# Age recovery

Recover the external Age identity from its independent copy and verify that it decrypts the site's SOPS material before changing the host. If the original was exposed, replace it through the supported site-recovery procedure and secure a new independent copy.

The identity must never be committed to Git, passed as a command argument, or pasted into logs. Keep it outside the site directory with the private recovery set described in [installation](../installation.md).
