# The nicer front door

Homepage does the pretty bits — cards, bookmarks, icons, and a background image —
so the little Go reader can concentrate on reading the lab. When `lab.yml`
changes, it writes a cleaned-up `services.yaml`, `bookmarks.yaml`, and
`settings.yaml` into Homepage's mounted config directory.

The reader should be the only process allowed to read `/etc/boetticher/lab.yml`.
It should:

1. notice changes on a short polling interval (or a filesystem notification);
2. accept explicit `control_surfaces` and module endpoint publications;
3. add observability and media links when the lab has made them unambiguous;
4. replace anything that looks like a secret with a fixed marker;
5. keep the same groups and order so the dashboard stops doing little dances.

Homepage needs a refresh after config changes. The deployment can call its local
refresh endpoint, or Caddy can send a small refresh hook to the reader. Keep
Homepage behind Caddy authentication; its API is not meant to sunbathe on the
open internet.

The built-in page stays around as a zero-dependency fallback and as the visual
reference for the Breaking Prod artwork, spacing, and green-and-cream theme.
