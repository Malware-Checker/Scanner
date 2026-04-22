use crate::{Finding, Severity};

const SIG: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub fn run(data: &[u8]) -> Vec<Finding> {
    if data.windows(SIG.len()).any(|w| w == SIG) {
        vec![Finding {
            engine: "eicar",
            signature: "EICAR-TEST-FILE".into(),
            description: "EICAR standard antivirus test file signature detected".into(),
            severity: Severity::Critical,
        }]
    } else {
        vec![]
    }
}
