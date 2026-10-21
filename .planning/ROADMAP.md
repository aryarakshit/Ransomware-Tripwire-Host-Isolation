# Roadmap: Deception-Based Ransomware Tripwire & Automated Host Isolation

## Overview

Build and verify a high-fidelity deception tripwire and automated containment system. The roadmap progresses through establishing deception configurations, production Wazuh & Sysmon XML rules, PowerShell deployment and active response scripts, Python simulation engine and safe T1486 attack simulator, real-time monitoring and active response integration with pytest suites, and finally benchmarking and automated portfolio reporting.

## Phases

- [x] **Phase 1: Workspace Initialization & Deception Configuration** - Establish project layout, `requirements.txt`, and `config/tripwire_config.yaml`.
- [x] **Phase 2: Wazuh FIM, Sysmon, & XML Detection Rules** - Create production Wazuh FIM configs, MITRE T1486 Level 15 detection rules, and Sysmon canary monitoring XML.
- [x] **Phase 3: Windows Deployment & Active Response Scripts** - Write PowerShell scripts for canary planting with SACLs, host isolation, restoration, and Atomic T1486 invocation.
- [x] **Phase 4: Sandbox Builder & Safe Atomic T1486 Simulator** - Build synthetic filesystem generator and reversible AES/Fernet encryption adversary.
- [x] **Phase 5: Real-Time FIM/Sysmon Engine, Active Response, & Unit Tests** - Implement event correlation engine, active response containment, and pytest validation suite.
- [x] **Phase 6: Master Benchmark Runner & Portfolio Case Study Report** - Implement metrics calculator, rich terminal benchmark runner, comprehensive case study report, and project README.

## Phase Details

### Phase 1: Workspace Initialization & Deception Configuration
**Goal**: Establish foundation configuration and directory structure.
**Depends on**: Nothing
**Requirements**: [CFG-01, DEP-01]
**Success Criteria**:
  1. `config/tripwire_config.yaml` is valid YAML matching the blueprint specification.
  2. `requirements.txt` specifies all necessary dependencies.
**Plans**: 1 plan
- [x] 01-01: Create directory tree, `requirements.txt`, and `config/tripwire_config.yaml`.

### Phase 2: Wazuh FIM, Sysmon, & XML Detection Rules
**Goal**: Author production Wazuh and Sysmon configurations for tripwire detection.
**Depends on**: Phase 1
**Requirements**: [WZH-01, WZH-02, WZH-03]
**Success Criteria**:
  1. `wazuh_configs/ossec_fim_whodata.conf` contains syscheck whodata and active-response bindings.
  2. `wazuh_configs/local_rules.xml` defines Level 15 rules 100201-100204 with PCRE2 regexes.
  3. `wazuh_configs/sysmon_canary_config.xml` is valid schema 4.90 monitoring Event IDs 11 & 23.
**Plans**: 1 plan
- [x] 02-01: Implement `ossec_fim_whodata.conf`, `local_rules.xml`, and `sysmon_canary_config.xml`.

### Phase 3: Windows Deployment & Active Response Scripts
**Goal**: Develop PowerShell automation for VM deployment and active response isolation.
**Depends on**: Phase 2
**Requirements**: [WIN-01, WIN-02, WIN-03, WIN-04]
**Success Criteria**:
  1. `deploy_canaries.ps1` sets SACLs and hashes decoys.
  2. `isolate_host.ps1` parses STDIN JSON, kills process tree, and configures firewall whitelist.
  3. `restore_host.ps1` restores firewall to default state.
  4. `invoke_atomic_t1486.ps1` safely runs local T1486 encryption.
**Plans**: 1 plan
- [x] 03-01: Implement all 4 PowerShell scripts in `windows_scripts/`.

### Phase 4: Sandbox Builder & Safe Atomic T1486 Simulator
**Goal**: Create local sandbox generator and safe ransomware adversary simulation.
**Depends on**: Phase 1
**Requirements**: [COR-01, COR-02]
**Success Criteria**:
  1. `sandbox_builder.py` populates 16 canaries and 500 dummy user files across 4 directories.
  2. `t1486_ransomware_sim.py` executes lexicographical traversal, encrypts with Fernet, renames to `.locked`, and responds immediately to termination signal.
**Plans**: 1 plan
- [x] 04-01: Implement `sandbox_builder.py` and `t1486_ransomware_sim.py`.

### Phase 5: Real-Time FIM/Sysmon Engine, Active Response, & Unit Tests
**Goal**: Implement real-time detection, containment engine, and unit test suite.
**Depends on**: Phase 2, Phase 4
**Requirements**: [COR-03, COR-04, TST-01, TST-02]
**Success Criteria**:
  1. `fim_sysmon_monitor.py` emits accurate Wazuh/Sysmon telemetry on canary modification.
  2. `active_response_engine.py` terminates simulator process tree upon Rule 100201 trigger.
  3. `pytest tests/` runs clean and achieves 100% pass rate.
**Plans**: 1 plan
- [x] 05-01: Implement `fim_sysmon_monitor.py`, `active_response_engine.py`, `test_wazuh_xml.py`, and `test_tripwire_containment.py`.

### Phase 6: Master Benchmark Runner & Portfolio Case Study Report
**Goal**: Implement metrics calculation, multi-run benchmark orchestrator, portfolio case study report, and README.
**Depends on**: Phase 3, Phase 5
**Requirements**: [COR-05, BMK-01, REP-01]
**Success Criteria**:
  1. `run_tripwire_benchmark.py` runs 5 iterations with rich live status tables.
  2. Benchmark measures $T_{\text{TTD}} < 1.0\text{s}$ and blast radius $< 1.0\%$.
  3. `reports/tripwire_study_report.md` generated with complete metrics and documentation.
  4. Complete `README.md` documenting architecture, deployment, and testing.
**Plans**: 1 plan
- [x] 06-01: Implement `metrics_calculator.py`, `run_tripwire_benchmark.py`, generate report, and write `README.md`.
