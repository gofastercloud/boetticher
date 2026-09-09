# Homepage-backed deployment

Homepage is a good production shell for this viewer: its YAML services/bookmarks,
custom CSS/JS, icons, and background image support cover the visual layer. The
small Go reader in this directory should become the adapter that writes a
sanitised `services.yaml`, `bookmarks.yaml`, and `settings.yaml` into a mounted
Homepage config directory whenever `lab.yml` changes.

That adapter should be the only process allowed to read `/etc/boetticher/lab.yml`.
It should:

1. parse the file on a short polling interval or filesystem notification;
2. accept explicit `control_surfaces` and module endpoint publications;
3. derive the current observability and media links when they are unambiguous;
4. replace secret-shaped values with a fixed marker before writing Homepage YAML;
5. preserve a stable group/order so the dashboard does not jump around.

Homepage needs its refresh action after config changes, so the deployment should
either call its local refresh endpoint or have Caddy route a small refresh hook
to the adapter. Keep Homepage behind Caddy authentication; its API routes are
otherwise intended for an authenticated deployment.

The existing custom page remains useful as a zero-dependency fallback and as a
visual reference for the Breaking Prod artwork, spacing, and green/cream theme.
