# Authoritative CVE Atlas specification

The original uploaded `CVE Atlas.docx` is preserved byte-for-byte inside the verified source archive parts in `source-archive/` because the repository connector used for the initial import accepts UTF-8 text but not direct binary file writes.

Materialize the original document locally:

```bash
./scripts/materialize-spec.sh
```

The command reconstructs the source archive, verifies archive SHA-256, extracts only `CVE Atlas.docx` into `.runtime/specification/`, and verifies the original document SHA-256:

```text
d2c81279d40c22961438fbc804311c444ae01574ad61766617f32210c180329e
```

No specification content is edited during this process.
