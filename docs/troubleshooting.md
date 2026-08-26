# Troubleshooting

Start with:

```sh
boetticher access --site my-boetticher
boetticher doctor --site my-boetticher
boetticher verify --site my-boetticher
```

If the HOME-side address may have changed, use only the known address with `boetticher bootstrap-endpoint set ADDRESS`; do not scan. Use `boetticher ssh-config --check` to check an operator file without rewriting it. Use `boetticher verify --ssh-journey` only when you want a real authenticated command through the bastion.

Interpretation matters:

- `CURRENT` means a generated projection contains the current model revision.
- `ABSENT` means a projection or evidence file has not been generated.
- `INCONSISTENT` means it is stale, malformed, or not safe to use.
- `NOT TESTED`, `HOLD`, and `INCONCLUSIVE` are preserved until the required live evidence exists.
- A passing local plan, formatter, or API fixture does not prove deployment, authenticated journeys, or physical client isolation.
