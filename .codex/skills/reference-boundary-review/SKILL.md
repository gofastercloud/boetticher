---
name: reference-boundary-review
description: Review a repository for hard-coded operational facts, reference-architecture bindings, and material that must never be committed.
metadata:
  short-description: Audit code/reference/secrets boundaries
---

# Reference-boundary review

Use this skill when a repository needs an evidence-based check that code does
not accidentally embed site-specific infrastructure or sensitive information.

## Classification

- **Code**: stable behavior, protocol values, schemas, safe defaults, and
  capability logic. Keep these in code when they are product invariants.
- **Reference architecture**: deliberately documented deployment bindings such
  as private IP ranges, VM IDs, hostnames, interface names, hardware models,
  VLAN names, and topology. Keep these together in clearly named reference
  files or examples, not scattered through implementation logic. Mark examples
  as examples when they are not authoritative.
- **Never committed**: secrets and credentials; private keys, tokens, cookies,
  recovery material; personal names/contact details; private or identifying
  domains and hostnames; real customer or household data; and unredacted
  inventories. Replace with placeholders or runtime secret-store/config input.

## Review workflow

1. Establish the target revision and read repository guidance. Preserve dirty
   state and do not print secret values.
2. Inventory likely bindings and sensitive material with narrow searches for
   IP/MAC addresses, VM IDs, hostnames/domains, interface/VLAN names, key/token
   markers, private-key headers, personal names/emails, and embedded inventory.
3. For every hit, classify it as code, reference architecture, generated/test
   fixture, or never-committed material. Check whether the file is clearly
   named, documented, and consumed as intended.
4. Flag hard-coded site facts in implementation, duplicated bindings, secrets
   in tracked files, private domains in public docs/Pages, and examples that
   look authoritative. Do not flag safe protocol constants or synthetic test
   fixtures without evidence.
5. Make only scoped fixes when requested or clearly necessary: move bindings to
   the existing reference/config path, replace sensitive values with explicit
   placeholders, and update tests/docs. Never invent production values.
6. Verify with `git diff --check`, focused tests, secret-pattern scans, and
   reference-link checks. Report findings with severity, file/line, evidence,
   classification, and recommended or completed action. Keep PASS/HOLD/FAIL/
   NOT TESTED distinct; source review is not live or secret-store proof.

## Output contract

Lead with the disposition. Separate findings by the three classifications,
then list fixes and verification. Redact secret-like values and personal data;
show at most a safe prefix or a placeholder.
