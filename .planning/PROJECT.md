# Deception-Based Ransomware Tripwire & Automated Host Isolation (ransomware-tripwire-soc)

## What This Is

A real-time deception and automated containment system designed to stop ransomware encryption attacks (MITRE ATT&CK T1486) within milliseconds. It seeds lexicographical canary files (honeytokens) across target directories, detects tampering via Windows Auditing/Sysmon and Wazuh FIM with whodata, and triggers immediate automated process termination and network isolation.

## Core Value

Stop ransomware attacks at the first touched file in < 1.0 second, preserving > 99% of user files with zero false positives.

## Context

Signature-based antivirus often fails against novel or custom-packed ransomware strains. Deception tripwires exploit a universal behavioral requirement of ransomware—iterating through directories and encrypting files in lexicographical order. Because legitimate users and system processes have zero reason to modify hidden canary files, any modification or deletion produces a high-fidelity, near-zero false-positive alert that triggers automated host containment.

## Constraints

- **Dual-Mode Execution**: Production-ready Windows PowerShell scripts, Sysmon XML configs, and Wazuh XML rules for deployment on a real Windows Lab VM, AND a self-contained Python simulation & benchmarking engine (`run_tripwire_benchmark.py`).
- **Safe Lab Containment**: The Wazuh Active Response firewall isolation rule must block all inbound/outbound traffic except the Wazuh Manager IP so the SOC retains visibility and control.
- **Performance Thresholds**: Target Time-to-Detect ($T_{\text{TTD}}$) < 1.0s, File Blast Radius ($B_{\text{affected}}$) < 1.0% (preservation > 99%).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Lexicographical prefix baiting (`!000_`, `#000_`, `$000_`, `_000_`) | Exploit Windows `FindFirstFileW`/`FindNextFileW` traversal order to force ransomware to touch bait first | ✓ Good |
| Dual-mode architecture (Production configs + Python simulation engine) | Enables local deterministic testing and verification on any machine while providing enterprise SOC deployment assets | ✓ Good |
| Whitelist Wazuh Manager during host quarantine | Prevents isolation of endpoint from SOC telemetry and management | ✓ Good |

---
*Last updated: 2026-10-21 after initialization*
