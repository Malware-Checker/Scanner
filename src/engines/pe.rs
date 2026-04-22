use crate::{Finding, Severity};
use goblin::pe::PE;

// Functions commonly abused for process injection, keylogging, and persistence.
// Legitimate software rarely imports these — seeing them is a strong signal.
const SUSPICIOUS_IMPORTS: &[(&str, &str, Severity)] = &[
    ("VirtualAllocEx",       "PROC_INJECT_ALLOC",    Severity::High),
    ("WriteProcessMemory",   "PROC_INJECT_WRITE",    Severity::High),
    ("CreateRemoteThread",   "PROC_INJECT_THREAD",   Severity::High),
    ("NtUnmapViewOfSection", "PROC_HOLLOW",          Severity::High),
    ("SetWindowsHookEx",     "KEYLOGGER_HOOK",       Severity::High),
    ("GetAsyncKeyState",     "KEYLOGGER_ASYNC",      Severity::Medium),
    ("URLDownloadToFile",    "DOWNLOADER",           Severity::High),
    ("InternetOpenUrl",      "NETWORK_FETCH",        Severity::Medium),
    ("RegSetValueEx",        "REGISTRY_PERSIST",     Severity::Medium),
    ("ShellExecuteEx",       "SHELL_EXEC",           Severity::Low),
    ("CryptEncrypt",         "CRYPTO_ENCRYPT",       Severity::Low),
    ("IsDebuggerPresent",    "ANTI_DEBUG",           Severity::Low),
    ("CheckRemoteDebuggerPresent", "ANTI_DEBUG_REMOTE", Severity::Low),
];

// Well-known packer/protector section names.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    (".upx0",   "UPX_PACKER"),
    (".upx1",   "UPX_PACKER"),
    (".upx2",   "UPX_PACKER"),
    (".nsp0",   "NSPACK_PACKER"),
    (".nsp1",   "NSPACK_PACKER"),
    (".aspack", "ASPACK_PACKER"),
    (".adata",  "ASPACK_PACKER"),
    (".themida","THEMIDA_PROTECTOR"),
    (".vmp0",   "VMPROTECT"),
    (".vmp1",   "VMPROTECT"),
];

fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&c| c > 0).fold(0.0, |acc, &c| {
        let p = c as f64 / len;
        acc - p * p.log2()
    })
}

pub fn run(data: &[u8]) -> Vec<Finding> {
    // Only attempt PE parsing if the file starts with the MZ magic bytes.
    if data.len() < 2 || &data[..2] != b"MZ" {
        return vec![];
    }

    let pe = match PE::parse(data) {
        Ok(p) => p,
        Err(_) => return vec![],
    };

    let mut findings = Vec::new();

    // Check imported function names against the suspicious list.
    for import in &pe.imports {
        for &(name, sig, ref sev) in SUSPICIOUS_IMPORTS {
            if import.name.eq_ignore_ascii_case(name) {
                let severity = match sev {
                    Severity::Low => Severity::Low,
                    Severity::Medium => Severity::Medium,
                    Severity::High => Severity::High,
                    Severity::Critical => Severity::Critical,
                };
                findings.push(Finding {
                    engine: "pe",
                    signature: sig.into(),
                    description: format!("Suspicious import: {name}"),
                    severity,
                });
            }
        }
    }

    // Check section names for known packers and high per-section entropy.
    for section in &pe.sections {
        let name = section.name().unwrap_or("?").to_ascii_lowercase();
        let name = name.trim_end_matches('\0');

        for &(packed_name, sig) in PACKER_SECTIONS {
            if name == packed_name {
                findings.push(Finding {
                    engine: "pe",
                    signature: sig.into(),
                    description: format!("Known packer section name found: {name}"),
                    severity: Severity::High,
                });
            }
        }

        // A section inside a PE with very high entropy means that section is
        // likely encrypted/packed at runtime — a common malware self-protection trick.
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        if let Some(section_data) = data.get(start..start + size) {
            let e = shannon(section_data);
            if e > 7.2 && size > 256 {
                findings.push(Finding {
                    engine: "pe",
                    signature: "PACKED_SECTION".into(),
                    description: format!("Section '{name}' has entropy {e:.2} — likely packed or encrypted"),
                    severity: Severity::Medium,
                });
            }
        }
    }

    findings
}
