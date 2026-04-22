pub enum Verdict {
    Clean,
    Malicious,
}

pub struct Finding {
    pub engine: &'static str,
    pub signature: &'static str,
    pub description: &'static str,
}

pub struct ScanResult {
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
}

pub fn scan(data: &[u8]) -> ScanResult {
    let engines: &[fn(&[u8]) -> Option<Finding>] = &[check_eicar];

    let findings: Vec<Finding> = engines.iter().filter_map(|e| e(data)).collect();

    let verdict = if findings.is_empty() {
        Verdict::Clean
    } else {
        Verdict::Malicious
    };

    ScanResult { verdict, findings }
}

// EICAR is a standardised benign test string — all AV engines must flag it.
// Sliding window handles files where the signature isn't at offset 0.
fn check_eicar(data: &[u8]) -> Option<Finding> {
    const SIG: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    if data.windows(SIG.len()).any(|w| w == SIG) {
        Some(Finding {
            engine: "eicar",
            signature: "EICAR-TEST-FILE",
            description: "EICAR test signature detected",
        })
    } else {
        None
    }
}
