# Requirements: Deception-Based Ransomware Tripwire & Automated Host Isolation

**Defined:** 2026-10-21
**Core Value:** Stop ransomware attacks at the first touched file in < 1.0 second, preserving > 99% of user files with zero false positives.

## v1 Requirements

### Configuration & Infrastructure
- [x] **CFG-01**: Create `config/tripwire_config.yaml` specifying canary filenames, prefixes, monitored directories, Wazuh manager IP, and SLA thresholds.
- [x] **DEP-01**: Create `requirements.txt` containing required dependencies (`pyyaml`, `rich`, `pytest`, `tabulate`, `cryptography`).

### Wazuh & Sysmon Detection Rules
- [x] **WZH-01**: Create `wazuh_configs/ossec_fim_whodata.conf` with `<syscheck>` whodata="yes", realtime="yes", and active-response bindings for rules 100201-100203.
- [x] **WZH-02**: Create `wazuh_configs/local_rules.xml` containing custom Wazuh rules 100201-100204 (Level 15, MITRE T1486) with PCRE2 regexes matching canary prefixes (`!000_`, `#000_`, `\$000_`, `_000_`).
- [x] **WZH-03**: Create `wazuh_configs/sysmon_canary_config.xml` valid Sysmon schema v4.90 monitoring Event ID 11 (FileCreate) and Event ID 23 (FileDelete) on canary paths.

### Windows Deployment & Active Response
- [x] **WIN-01**: Implement `windows_scripts/deploy_canaries.ps1` to plant bait files with realistic headers, set Windows SACL Auditing, and generate `canary_manifest.json`.
- [x] **WIN-02**: Implement `windows_scripts/isolate_host.ps1` as Wazuh Active Response script parsing STDIN JSON, terminating offending PID, and isolating network via `netsh advfirewall` while whitelisting the Wazuh Manager IP.
- [x] **WIN-03**: Implement `windows_scripts/restore_host.ps1` to reset Windows Firewall policies and remove containment rules.
- [x] **WIN-04**: Implement `windows_scripts/invoke_atomic_t1486.ps1` safe Atomic Red Team T1486 test execution wrapper.

### Core Simulation Engine
- [x] **COR-01**: Implement `core/sandbox_builder.py` to create isolated sandbox directory with 4 subdirectories, 16 canary files, and 500 dummy user files.
- [x] **COR-02**: Implement `core/t1486_ransomware_sim.py` simulating ransomware directory traversal, Fernet encryption, `.locked` renaming, and immediate cancellation handling.
- [x] **COR-03**: Implement `core/fim_sysmon_monitor.py` watching sandbox in real-time, emitting authentic Wazuh FIM whodata and Sysmon Event ID 11 JSON events.
- [x] **COR-04**: Implement `core/active_response_engine.py` correlating events against `local_rules.xml`, terminating the attacker PID, and generating firewall isolation audit log.
- [x] **COR-05**: Implement `core/metrics_calculator.py` calculating $T_{\text{TTD}}$, $T_{\text{TTI}}$, Blast Radius %, and Preservation Rate %.

### Testing & Quality Assurance
- [x] **TST-01**: Implement `tests/test_wazuh_xml.py` validating that `local_rules.xml` and `sysmon_canary_config.xml` are valid XML and match canary patterns.
- [x] **TST-02**: Implement `tests/test_tripwire_containment.py` verifying end-to-end containment stops T1486 before > 5% of files are encrypted.

### Benchmarking & Reporting
- [x] **BMK-01**: Implement `run_tripwire_benchmark.py` running 5 simulation runs with rich terminal tables showing millisecond timing.
- [x] **REP-01**: Generate `reports/tripwire_study_report.md` with attack-to-isolation timeline, blast radius metrics, XML snippets, and resume bullet point.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CFG-01 | Phase 1 | Completed |
| DEP-01 | Phase 1 | Completed |
| WZH-01 | Phase 2 | Completed |
| WZH-02 | Phase 2 | Completed |
| WZH-03 | Phase 2 | Completed |
| WIN-01 | Phase 3 | Completed |
| WIN-02 | Phase 3 | Completed |
| WIN-03 | Phase 3 | Completed |
| WIN-04 | Phase 3 | Completed |
| COR-01 | Phase 4 | Completed |
| COR-02 | Phase 4 | Completed |
| COR-03 | Phase 5 | Completed |
| COR-04 | Phase 5 | Completed |
| COR-05 | Phase 6 | Completed |
| TST-01 | Phase 5 | Completed |
| TST-02 | Phase 5 | Completed |
| BMK-01 | Phase 6 | Completed |
| REP-01 | Phase 6 | Completed |

**Coverage:**
- v1 requirements: 18 total
- Mapped to phases: 18
- Completed: 18
- Unmapped: 0
