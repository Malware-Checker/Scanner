use crate::{Finding, Severity};

// Shannon entropy: 0 (all same byte) to 8 (perfectly random).
// Packed/encrypted data sits above ~7.2 — common in malware that obfuscates itself.
fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0, |acc, &c| {
            let p = c as f64 / len;
            acc - p * p.log2()
        })
}

pub fn run(data: &[u8]) -> Vec<Finding> {
    let e = shannon(data);

    if e > 7.5 {
        vec![Finding {
            engine: "entropy",
            signature: "HIGH_ENTROPY".into(),
            description: format!("File entropy is {e:.2}/8.0 — strongly suggests encryption or packing"),
            severity: Severity::High,
        }]
    } else if e > 7.0 {
        vec![Finding {
            engine: "entropy",
            signature: "ELEVATED_ENTROPY".into(),
            description: format!("File entropy is {e:.2}/8.0 — may indicate compression or obfuscation"),
            severity: Severity::Medium,
        }]
    } else {
        vec![]
    }
}
