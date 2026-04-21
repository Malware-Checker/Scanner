# Scanner

Rust crate responsible for analysing files and detecting malware. Called by the Backend API after a file is uploaded.

## Status

Under active development. Current detection:
- EICAR test signature (end-to-end pipeline validation)

Planned:
- Signature-based detection (YARA rules)
- Heuristic analysis
- Hash lookups against threat intelligence feeds

## Running

```bash
cargo run
```

## Integration

The Backend API will call into this crate directly once the scanner logic is complete. For now detection runs inline in the API handler.
