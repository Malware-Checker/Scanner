# Scanner

Rust library crate for static malware analysis. Called by the Backend API after a file upload. Returns a structured `ScanResult` with a verdict, cumulative threat score, and a list of findings from each engine.

## Usage

```rust
use scanner::{scan, Verdict};

let result = scanner::scan(&file_bytes);

match result.verdict {
    Verdict::Clean     => println!("clean"),
    Verdict::Suspicious => println!("suspicious — score {}", result.score),
    Verdict::Malicious  => println!("malicious — score {}", result.score),
}
```

## Scoring

| Severity | Score |
|----------|-------|
| Low      | 5     |
| Medium   | 15    |
| High     | 30    |
| Critical | 100   |

Score ≥ 50 or any Critical finding → `Malicious`. Score > 0 → `Suspicious`. Score = 0 → `Clean`.

## Detection engines

| Engine | What it detects | How |
|--------|----------------|-----|
| `eicar` | EICAR test file | Exact signature match (Critical) |
| `entropy` | Packed / encrypted files | Shannon entropy > 7.0 (Medium), > 7.5 (High) |
| `pe` | Malicious Windows binaries | Parses PE headers — 13 suspicious imports, 9 packer section names, per-section entropy |
| `strings` | Malware techniques in any file | 25 high-signal string indicators across injection, persistence, download cradles, keylogging, anti-analysis |

## Adding a new engine

1. Create `src/engines/your_engine.rs` with a `pub fn run(data: &[u8]) -> Vec<Finding>` function
2. Add `pub mod your_engine;` to `src/engines/mod.rs`
3. Call `your_engine::run(data)` inside `scan()` in `src/lib.rs`

## Dependencies

- [goblin](https://github.com/m4b/goblin) — pure-Rust PE/ELF/Mach-O parser
