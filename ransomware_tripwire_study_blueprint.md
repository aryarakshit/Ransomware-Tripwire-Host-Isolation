# Ransomware Tripwire: AI Agent Implementation Blueprint

This specification is designed for an autonomous AI coding agent (e.g., Cursor, Claude Code, Windsurf, GitHub Copilot) to build, test, and benchmark a Deception-Based Ransomware Tripwire & Automated Host Isolation system.

## 1. Project Overview & Objectives

* **Project Name:** Deception-Based Ransomware Tripwire & Automated Host Isolation (`ransomware-tripwire-soc`)
* **Mission:** Deploy strategically named canary files (honeytokens) across high-value directories on a Windows endpoint, monitor them in real time using Sysmon and Wazuh File Integrity Monitoring (FIM) with `whodata` auditing, and trigger an automated Wazuh Active Response script that terminates the offending process and network-isolates the host upon detecting Atomic Red Team `T1486` (Data Encrypted for Impact).
* **Why It Stands Out:** Signature-based antivirus often fails against novel or custom-packed ransomware strains. Deception tripwires exploit a universal behavioral requirement of ransomware—iterating through directories and encrypting files. Because legitimate users and system processes have zero reason to modify hidden canary files, any modification or deletion produces a **high-fidelity, near-zero false-positive alert** that can safely trigger automated host containment within milliseconds.
* **Key Constraints:**
  * **Dual-Mode Execution:** Must generate production-ready Windows PowerShell scripts, Sysmon XML configs, and Wazuh XML rules for deployment on a real Windows Lab VM, **AND** include a self-contained Python simulation & benchmarking engine (`run_tripwire_benchmark.py`) that executes a safe local `T1486` encryption test in a sandbox folder to measure exact millisecond Time-to-Detect ($T_{\text{TTD}}$), Time-to-Isolate ($T_{\text{TTI}}$), and File Blast Radius ($B_{\text{affected}}$).
  * **Safe Lab Containment:** The Wazuh Active Response firewall isolation rule must block all inbound/outbound traffic *except* the Wazuh Manager IP so the SOC retains visibility and remote control of the quarantined host.

---

## 2. System Architecture & Pipeline Flowchart

### A. Mermaid Flowchart Diagram

*Note: You can view this natively in GitHub, Cursor, Notion, Obsidian, or any Markdown previewer that supports Mermaid.*

```mermaid
flowchart TD
    %% Stage 1: Deception Seeding
    subgraph SEEDING["1. DECEPTION & CANARY SEEDING LAYER"]
        A["Canary Deployer (deploy_canaries.ps1)"] --> B["Plant Lexicographical Bait Files<br/>(!000_Financial_Ledger.xlsx, #000_Passwords.docx)"]
        B --> C["Target High-Value Directories<br/>(Desktop, Documents, Public, Finance Shares)"]
        C --> D["Record Baseline SHA-256 Hashes & SACL Audit ACLs"]
    end

    %% Stage 2: Adversary Execution
    subgraph ATTACK["2. ADVERSARY EXECUTION (ATOMIC RED TEAM T1486)"]
        E["Attacker / Atomic T1486 Runner"] --> F["Directory Traversal (FindFirstFileW)<br/>Hits '!' and '#' Canary Files First"]
        F --> G["Read, Encrypt (AES-256), Overwrite, or Rename<br/>(*.locked / *.encrypted)"]
    end

    %% Stage 3: Telemetry & Detection
    subgraph DETECTION["3. KERNEL & FIM TELEMETRY (SYSMON + WAZUH)"]
        G --> H["Sysmon Driver<br/>(Event ID 11: FileCreate, ID 23: FileDelete)"]
        G --> I["Wazuh FIM (syscheck)<br/>(realtime='yes', whodata='yes' via Windows Audit)"]
        H --> J["Wazuh Manager Correlation Engine<br/>(rules/local_rules.xml: Rules 100201 - 100204)"]
        I --> J
        J --> K{"Canary File Touched?<br/>(Severity Level 15 | MITRE T1486)"}
    end

    %% Stage 4: Automated Active Response
    subgraph RESPONSE["4. WAZUH ACTIVE RESPONSE (SOAR CONTAINMENT)"]
        K -- YES --> L["Trigger Active Response Command<br/>(isolate-ransomware-host.cmd / .ps1)"]
        L --> M["Step 1: Extract Process ID (PID) from Whodata / Sysmon<br/>Execute taskkill /F /PID &lt;offending_pid&gt;"]
        M --> N["Step 2: Quarantine Host via Windows Firewall<br/>(netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound)"]
        N --> O["Step 3: Whitelist Wazuh Manager IP Only<br/>(Maintain SOC Telemetry & Management Channel)"]
    end

    %% Stage 5: Metrics & Forensics
    subgraph REPORTING["5. FORENSIC CAPTURE & BLAST RADIUS METRICS"]
        O --> P["Capture Forensic Snapshot<br/>(Process Tree, CommandLine, User SID, File Hashes)"]
        P --> Q["Calculate Time-to-Detect (TTD), Time-to-Isolate (TTI),<br/>and % of User Files Saved"]
        Q --> R["Auto-Generate Portfolio Case Study<br/>(reports/tripwire_study_report.md)"]
    end

    %% Styling
    style SEEDING fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc
    style ATTACK fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#f8fafc
    style DETECTION fill:#1e293b,stroke:#a855f7,stroke-width:2px,color:#f8fafc
    style RESPONSE fill:#1e293b,stroke:#f59e0b,stroke-width:2px,color:#f8fafc
    style REPORTING fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc
```

### B. Text / ASCII Flow Representation

```
+-------------------------------------------------------------------------+
|                 STAGE 1: DECEPTION & CANARY SEEDING                     |
|  - Plant lexicographically first bait files (!000_Payroll_2026.xlsx)    |
|  - Configure Windows SACL Auditing + Wazuh FIM (whodata="yes")          |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|             STAGE 2: ATOMIC RED TEAM T1486 EXECUTION                    |
|  - Simulated ransomware enumerates folders alphabetically               |
|  - Touches/Encrypts '!000_...' canary files before real user documents  |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|           STAGE 3: SYSMON & WAZUH FIM REAL-TIME DETECTION               |
|  - Captures Sysmon Event IDs 11/23 & Wazuh FIM Whodata Audit Event 4663 |
|  - Fires Wazuh Custom Rule 100201 / 100202 (Level 15 - MITRE T1486)     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|         STAGE 4: AUTOMATED ACTIVE RESPONSE (< 2.0 SECONDS)              |
|  1. Kill offending encryption process tree (taskkill /F /T /PID)        |
|  2. Block all host network traffic via Windows Firewall (netsh)         |
|  3. Permit only Wazuh Manager IP (TCP 1514/1515) for SOC control        |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|             STAGE 5: BLAST RADIUS & LATENCY BENCHMARKING                |
|  - Compute Time-to-Detect (TTD) & Time-to-Isolate (TTI)                 |
|  - Verify >98% of dummy user files survived unencrypted                 |
|  - Output Portfolio Report (reports/tripwire_study_report.md)           |
+-------------------------------------------------------------------------+
```

### C. Stage-by-Stage Data Flow Specification

| Stage | Input | Processing | Output |
| :--- | :--- | :--- | :--- |
| **1. Seeding** | `config/tripwire_config.yaml` | Generate realistic decoy files prefixed with `!000_` and `.000_`; record SHA-256 baseline | Canary manifest JSON & monitored directory tree |
| **2. T1486 Attack** | Atomic Red Team `T1486` test script | Traverse target directories and encrypt files sequentially with simulated I/O pacing | File modification/rename events (`*.locked`) & timestamps |
| **3. Detection** | FIM Whodata / Sysmon Event ID 11 & 23 | Match touched file path against canary manifest via Wazuh `local_rules.xml` (`100201`–`100204`) | Level 15 high-priority alert with offending `process_id` and `process_name` |
| **4. Containment** | Wazuh Level 15 Alert JSON payload | Execute Active Response script: terminate `process_id` and apply `netsh advfirewall` quarantine | Terminated ransomware PID & network-isolated endpoint |
| **5. Benchmarking** | Attack start $t_0$, Alert $t_1$, Isolation $t_2$ | Calculate $T_{\text{TTD}}$, $T_{\text{TTI}}$, and count affected vs. preserved user files | `reports/tripwire_study_report.md` & resume metrics |

---

## 3. Directory Layout to Generate

The AI agent must initialize the workspace with the following structure:

```
ransomware-tripwire-soc/
├── config/
│   ├── __init__.py
│   └── tripwire_config.yaml          # Canary filenames, target directories, SLA thresholds
├── wazuh_configs/
│   ├── ossec_fim_whodata.conf        # Wazuh Agent <syscheck> & <active-response> config
│   ├── local_rules.xml               # Wazuh Manager custom rules (IDs 100200-100205)
│   └── sysmon_canary_config.xml      # Sysmon configuration targeting canary paths (IDs 11, 23)
├── windows_scripts/
│   ├── deploy_canaries.ps1           # PowerShell script to plant canaries & set ACLs on VM
│   ├── isolate_host.ps1              # Wazuh Active Response script (process kill + netsh firewall)
│   ├── restore_host.ps1              # Rollback script to un-isolate the lab VM after testing
│   └── invoke_atomic_t1486.ps1       # PowerShell wrapper for Atomic Red Team T1486 test
├── core/
│   ├── __init__.py
│   ├── sandbox_builder.py            # Creates local test sandbox with 500 user files + canaries
│   ├── fim_sysmon_monitor.py         # Real-time file & process monitor simulating Wazuh FIM + Sysmon
│   ├── active_response_engine.py     # Executes process termination & simulated/dry-run firewall lock
│   ├── t1486_ransomware_sim.py       # Safe, reversible Atomic T1486 file encryption simulator
│   └── metrics_calculator.py         # Computes TTD, TTI, and file blast radius statistics
├── reports/
│   └── tripwire_study_report.md      # Auto-generated portfolio report with timeline & metrics
├── tests/
│   ├── test_wazuh_xml.py             # Validates local_rules.xml and sysmon_canary_config.xml
│   └── test_tripwire_containment.py  # Verifies T1486 is stopped before >5% of files are encrypted
├── requirements.txt
├── run_tripwire_benchmark.py         # Master orchestrator for end-to-end simulation & report
└── README.md
```

---

## 4. Deception Strategy & Configuration (`config/tripwire_config.yaml`)

Ransomware families typically enumerate directories using Windows API calls (`FindFirstFileW` / `FindNextFileW`), which return files in **NTFS lexicographical (ASCII) sort order**. By naming canary files with leading punctuation (`!`, `#`, `$`), the ransomware is forced to touch and encrypt the canary files **before** reaching real user files (`A`–`Z`).

The agent must generate `config/tripwire_config.yaml` with the following specification:

```yaml
experiment_settings:
  total_dummy_user_files: 500
  encryption_speed_ms_per_file: 15
  wazuh_manager_ip: "192.168.56.10"
  max_allowed_blast_radius_pct: 5.0
  target_ttd_seconds: 1.5

monitored_directories:
  - "C:\\Users\\Public\\Documents"
  - "C:\\Users\\LabAdmin\\Desktop"
  - "C:\\Users\\LabAdmin\\Documents"
  - "C:\\Shares\\Finance_Records"

canary_files:
  - filename: "!000_CONFIDENTIAL_Payroll_2026.xlsx"
    type: "spreadsheet_honeytoken"
    magic_header: "PK\\x03\\x04"
    description: "Lexicographical first-hit Excel decoy containing fake salary tables"
  - filename: "#000_AWS_Production_Root_Keys.txt"
    type: "credential_honeytoken"
    content_prefix: "AKIAIOSFODNN7EXAMPLE"
    description: "Fake cloud credential file placed at top of directory sort order"
  - filename: "$000_Executive_M&A_Targets.docx"
    type: "document_honeytoken"
    magic_header: "PK\\x03\\x04"
    description: "High-value M&A decoy document"
  - filename: "_000_Backup_Recovery_Seeds.pdf"
    type: "pdf_honeytoken"
    magic_header: "%PDF-1.7"
    description: "Decoy recovery vault document"

wazuh_rule_ids:
  canary_modified: "100201"
  canary_deleted: "100202"
  sysmon_canary_create_overwrite: "100203"
  active_response_isolated: "100204"
```

---

## 5. Module & Artifact Implementation Details for the Agent

### A. Production Wazuh & Sysmon Configs (`wazuh_configs/`)

1. **`wazuh_configs/ossec_fim_whodata.conf`:**
   * Configure `<syscheck>` with `<directories check_all="yes" realtime="yes" whodata="yes" report_changes="yes">` for the target canary paths.
   * Configure `<command>` and `<active-response>` blocks on the Wazuh Manager to trigger `isolate_host.cmd` / `isolate_host.ps1` automatically whenever rules `100201`, `100202`, or `100203` fire (Severity Level $\ge 15$).

2. **`wazuh_configs/local_rules.xml`:**
   * Rule `100201` (Level 15): Child of Wazuh FIM rule `550` (Integrity checksum changed). Matches `<field name="file" type="pcre2">(?i)(!000_|#000_|\$000_|_000_)</field>`. Mapped to `<mitre><id>T1486</id></mitre>`.
   * Rule `100202` (Level 15): Child of Wazuh FIM rule `553` (File deleted). Matches the same canary regex pattern. Mapped to `<mitre><id>T1486</id></mitre>`.
   * Rule `100203` (Level 15): Child of Sysmon Event ID 11 (`61613`) or Event ID 23 (`92213`). Matches `<field name="win.eventdata.targetFilename" type="pcre2">(?i)(!000_|#000_|\$000_|_000_)</field>`.
   * Rule `100204` (Level 12): Confirms Active Response host isolation succeeded.

3. **`wazuh_configs/sysmon_canary_config.xml`:**
   * Valid Sysmon schema (`schemaversion="4.90"`) monitoring `FileCreate` (Event ID 11) and `FileDelete` (Event ID 23) where `TargetFilename` contains `!000_`, `#000_`, `$000_`, or `_000_`.

### B. Windows Deployment & Active Response Scripts (`windows_scripts/`)

1. **`windows_scripts/deploy_canaries.ps1`:**
   * Creates the canary files across the target directories with realistic file headers and fake data sizes ($15\text{ KB}$ – $120\text{ KB}$), records their SHA-256 hashes into `canary_manifest.json`, and configures Windows File System Audit ACLs (`System.Security.AccessControl.FileSystemAuditRule`) so Wazuh `whodata` captures the exact offending Process ID (`PID`) and User Account.

2. **`windows_scripts/isolate_host.ps1`:**
   * Reads the Wazuh Active Response JSON input from `STDIN`.
   * Extracts `data.audit.process_id` (from FIM `whodata`) or `data.win.eventdata.processId` (from Sysmon) and immediately executes `Stop-Process -Id $pid -Force` to halt encryption in-flight.
   * Executes `netsh advfirewall` commands to allow outbound/inbound traffic **only** to `$WazuhManagerIP` on ports `1514` and `1515`, and sets all firewall profiles to `blockinbound,blockoutbound`.

3. **`windows_scripts/invoke_atomic_t1486.ps1`:**
   * Safe wrapper that invokes the Atomic Red Team `T1486` test (or local PowerShell AES file encryption loop) strictly inside the designated test directory on the lab VM.

### C. Python Simulation & Benchmarking Engine (`core/`)

Because the AI agent and reviewer need to verify metrics deterministically on any machine (Linux, macOS, or Windows behind CGNAT), the Python `core/` engine runs a live, multi-threaded benchmark:

1. **`core/sandbox_builder.py`:**
   * Builds a local `sandbox_drive/` containing 4 subdirectories, 16 planted canary files (`!000_...`, `#000_...`), and $500$ realistic dummy user files (`Account_Statement_001.pdf` through `Project_Spec_500.docx`).

2. **`core/t1486_ransomware_sim.py`:**
   * Runs as an independent subprocess/thread representing the `T1486` adversary process.
   * Iterates through `sandbox_drive/` in standard lexicographical order, XOR/Fernet-encrypting each file and appending `.locked` at a realistic pace (e.g., $15\text{ ms}$ per file).

3. **`core/fim_sysmon_monitor.py` & `core/active_response_engine.py`:**
   * Monitors `sandbox_drive/` in real time, generates authentic Wazuh FIM Whodata & Sysmon Event ID 11 JSON logs, evaluates them against `wazuh_configs/local_rules.xml`, and upon hitting Rule `100201` (Level 15), triggers the Active Response engine to terminate the `t1486_ransomware_sim` thread/process and generate the firewall isolation audit log.

### D. Mathematical Metrics & Case Study Report (`core/metrics_calculator.py`)

Calculate and render the following metrics in `reports/tripwire_study_report.md`:

1. **Time-to-Detect ($T_{\text{TTD}}$):**
   $$T_{\text{TTD}} = t_{\text{alert\_fired}} - t_{\text{canary\_touched}}$$

2. **Time-to-Isolate ($T_{\text{TTI}}$):**
   $$T_{\text{TTI}} = t_{\text{host\_isolated}} - t_{\text{attack\_start}}$$

3. **File Blast Radius Percentage ($B_{\text{affected}}$):**
   $$B_{\text{affected}} = \left( \frac{F_{\text{user\_encrypted}}}{F_{\text{user\_total}}} \right) \times 100\%$$

4. **Data Preservation Rate ($R_{\text{saved}}$):**
   $$R_{\text{saved}} = 100\% - B_{\text{affected}}$$

---

## 6. Dependencies (`requirements.txt`)

```
pyyaml>=6.0.1
rich>=13.7.0
pytest>=8.0.0
tabulate>=0.9.0
cryptography>=42.0.0
```

---

## 7. Prompt Sequence for the AI Agent

Copy and paste these prompts sequentially into your AI coding assistant:

### Prompt 1: Workspace Initialization & Deception Configuration
> "Initialize the project directory structure defined in Section 3 of `ransomware_tripwire_blueprint.md`. Create `requirements.txt` and `config/tripwire_config.yaml` with the exact canary file definitions, lexicographical naming strategy, and SLA thresholds specified in Section 4."

### Prompt 2: Wazuh FIM, Sysmon, & XML Detection Rules
> "Create the three production configuration files in `wazuh_configs/`: (1) `ossec_fim_whodata.conf` with real-time `whodata=\"yes\"` monitoring and active-response bindings, (2) `local_rules.xml` with custom Wazuh rules `100201` to `100204` (Level 15, mapped to MITRE `T1486`) using PCRE2 regexes matching our canary prefixes (`!000_`, `#000_`, `$000_`, `_000_`), and (3) `sysmon_canary_config.xml` for Sysmon Event IDs 11 and 23."

### Prompt 3: Windows PowerShell Canary Deployer & Active Response Scripts
> "Implement the four PowerShell scripts in `windows_scripts/`: `deploy_canaries.ps1` (creates canary files, sets Windows Audit SACLs, writes SHA-256 manifest), `isolate_host.ps1` (Wazuh Active Response script that parses JSON from STDIN, kills the offending PID, and isolates the host via `netsh advfirewall` while whitelisting the Wazuh Manager IP), `restore_host.ps1` (restores firewall defaults), and `invoke_atomic_t1486.ps1` (Atomic Red Team T1486 test runner)."

### Prompt 4: Sandbox Builder & Safe Atomic T1486 Simulator
> "Implement `core/sandbox_builder.py` to create a local test directory containing 16 lexicographically ordered canary files and 500 dummy user files. Then implement `core/t1486_ransomware_sim.py` to simulate an Atomic Red Team T1486 encryption routine that traverses directories in lexicographical order, encrypts files, renames them with `.locked`, and supports immediate termination via signal/event when Active Response triggers."

### Prompt 5: Real-Time FIM/Sysmon Engine, Active Response, & Unit Tests
> "Implement `core/fim_sysmon_monitor.py` and `core/active_response_engine.py`. The monitor must watch the sandbox directory, emit authentic Wazuh FIM Whodata / Sysmon JSON events, evaluate them against `wazuh_configs/local_rules.xml`, and trigger Active Response to stop the `T1486` simulator and execute simulated host isolation. Create `tests/test_wazuh_xml.py` and `tests/test_tripwire_containment.py` and verify all tests pass with `pytest`."

### Prompt 6: Master Benchmark Runner & Portfolio Case Study Report
> "Implement `core/metrics_calculator.py` and `run_tripwire_benchmark.py`. Running `python run_tripwire_benchmark.py` should execute 5 benchmark runs, display live `rich` terminal tables showing exact millisecond timestamps, and generate `reports/tripwire_study_report.md` complete with the attack-to-isolation timeline, Wazuh XML snippets, blast radius metrics, and the populated resume bullet point."

---

## 8. Verification & Acceptance Criteria

Before marking the project complete, the AI agent must verify:

1. `wazuh_configs/local_rules.xml` and `wazuh_configs/sysmon_canary_config.xml` parse cleanly as valid XML with `xml.etree.ElementTree`.
2. `pytest tests/` passes $100\%$ of XML rule matching and containment assertions.
3. Running `python run_tripwire_benchmark.py` detects the `T1486` encryption routine on the very first canary file (`!000_CONFIDENTIAL_Payroll_2026.xlsx`) in $T_{\text{TTD}} < 1.0\text{ second}$ and isolates the host before $1\%$ of dummy user files are affected ($>99\%$ user data preserved).
4. `reports/tripwire_study_report.md` is automatically generated with complete metrics tables and ready for GitHub portfolio publication.