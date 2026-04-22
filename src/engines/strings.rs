use crate::{Finding, Severity};

// (needle, signature, description, severity)
// Ordered roughly by signal strength. Checked case-insensitively against the raw bytes.
const INDICATORS: &[(&str, &str, &str, Severity)] = &[
    // Persistence
    ("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "REG_AUTORUN", "Autorun registry key path", Severity::High),
    ("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "REG_WINLOGON", "Winlogon hijack path", Severity::High),

    // Download cradles
    ("URLDownloadToFile", "DOWNLOAD_CRADLE", "URLDownloadToFile string — download-and-execute pattern", Severity::High),
    ("powershell -enc",   "PS_ENCODED_CMD",  "Encoded PowerShell command", Severity::High),
    ("powershell -e ",    "PS_ENCODED_CMD",  "Encoded PowerShell command", Severity::High),
    ("IEX(",              "PS_IEX",          "PowerShell Invoke-Expression (remote code execution pattern)", Severity::High),
    ("Invoke-Expression", "PS_IEX",          "PowerShell Invoke-Expression", Severity::High),

    // Process injection / hollowing
    ("VirtualAllocEx",       "STR_INJECT_ALLOC",  "Process injection API string", Severity::High),
    ("WriteProcessMemory",   "STR_INJECT_WRITE",  "Process injection API string", Severity::High),
    ("CreateRemoteThread",   "STR_INJECT_THREAD", "Process injection API string", Severity::High),
    ("NtUnmapViewOfSection", "STR_PROC_HOLLOW",   "Process hollowing API string", Severity::High),

    // Privilege escalation
    ("SeDebugPrivilege",  "SE_DEBUG",    "SeDebugPrivilege — often used to access protected processes", Severity::Medium),
    ("token impersonation", "TOKEN_IMP", "Token impersonation string", Severity::Medium),

    // Dropper / loader indicators
    ("cmd.exe /c ",       "CMD_EXEC",    "Command shell execution string", Severity::Medium),
    ("wscript.exe",       "WSCRIPT",     "WScript execution", Severity::Medium),
    ("regsvr32 /s /u",    "REGSVR_LOL",  "Regsvr32 living-off-the-land technique", Severity::High),
    ("mshta ",            "MSHTA",       "MSHTA execution (commonly abused for HTA payloads)", Severity::High),
    ("certutil -decode",  "CERTUTIL",    "Certutil used to decode payload (living-off-the-land)", Severity::High),

    // Anti-analysis
    ("IsDebuggerPresent", "STR_ANTI_DBG",   "Anti-debugger check string", Severity::Low),
    ("VirtualBox",        "STR_VM_CHECK",   "Hypervisor name — possible VM detection", Severity::Low),
    ("VMware",            "STR_VM_CHECK",   "Hypervisor name — possible VM detection", Severity::Low),
];

pub fn run(data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for &(needle, sig, desc, ref sev) in INDICATORS {
        if seen.contains(sig) {
            continue;
        }
        if contains_ignore_case(data, needle.as_bytes()) {
            seen.insert(sig);
            let severity = match sev {
                Severity::Low => Severity::Low,
                Severity::Medium => Severity::Medium,
                Severity::High => Severity::High,
                Severity::Critical => Severity::Critical,
            };
            findings.push(Finding {
                engine: "strings",
                signature: sig.into(),
                description: desc.into(),
                severity,
            });
        }
    }

    findings
}

// Case-insensitive substring search over raw bytes without allocating.
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter().zip(needle.iter()).all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}
