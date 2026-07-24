# CVE Atlas Agent Instructions

The authoritative project specification is the original `CVE Atlas.docx`. It is preserved byte-for-byte in `docs/specification/source-archive/` and materialized with `./scripts/materialize-spec.sh` into `.runtime/specification/CVE Atlas.docx`.

Before changing code, every coding agent must:

1. Run `./scripts/verify-spec.sh` and read the complete materialized specification without editing it.
2. Read `README.md` and `docs/architecture/`.
3. Review migrations, tests, and open issues.
4. Implement only the currently approved milestone.
5. Preserve passive-by-default operation and the separation between passive intelligence and authorized validation.
6. Never add exploitation, password attacks, destructive checks, hidden administrative endpoints, or active scanning of unverified external targets.
7. Never call a possible CVE a confirmed vulnerability without owner confirmation or authorized validation evidence.
8. Update OpenAPI, migrations, tests, documentation, and changelog together with code changes.

The source archive and DOCX checksums are recorded in `docs/specification/source-archive/SHA256SUMS` and `docs/specification/SHA256SUMS`.
