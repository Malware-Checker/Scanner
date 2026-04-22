mod engines;

use engines::{eicar, entropy, pe, strings};

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

#[derive(Debug)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn score(&self) -> u32 {
        match self {
            Severity::Low => 5,
            Severity::Medium => 15,
            Severity::High => 30,
            Severity::Critical => 100,
        }
    }
}

#[derive(Debug)]
pub struct Finding {
    pub engine: &'static str,
    pub signature: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug)]
pub struct ScanResult {
    pub verdict: Verdict,
    pub score: u32,
    pub findings: Vec<Finding>,
}

pub fn scan(data: &[u8]) -> ScanResult {
    let mut findings: Vec<Finding> = Vec::new();

    findings.extend(eicar::run(data));
    findings.extend(entropy::run(data));
    findings.extend(pe::run(data));
    findings.extend(strings::run(data));

    let score: u32 = findings.iter().map(|f| f.severity.score()).sum();

    let verdict = if findings.iter().any(|f| matches!(f.severity, Severity::Critical)) || score >= 50 {
        Verdict::Malicious
    } else if score > 0 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    ScanResult { verdict, score, findings }
}
