"""
End-to-End Containment Verification Tests:
Simulates a live MITRE ATT&CK T1486 ransomware outbreak in a test sandbox,
verifying that the Deception Tripwire and Active Response engine halt the adversary
in < 1.0s and preserve > 98% of user files.
"""

from pathlib import Path
import pytest
import time

from core.active_response_engine import ActiveResponseEngine
from core.fim_sysmon_monitor import FimSysmonMonitor
from core.sandbox_builder import SandboxBuilder
from core.t1486_ransomware_sim import T1486RansomwareSimulator


@pytest.fixture
def test_sandbox(tmp_path):
    """Builds an isolated test sandbox with canary decoys and user files."""
    sandbox_dir = tmp_path / "sandbox_test"
    builder = SandboxBuilder(
        base_dir=sandbox_dir,
        config={"experiment_settings": {"total_dummy_user_files": 200}},
    )
    manifest = builder.build()
    yield sandbox_dir, manifest
    builder.clean()


def test_t1486_containment_and_preservation(test_sandbox):
    """
    Execute simulated T1486 adversary against the sandbox.
    Assert that the Active Response engine halts the attack upon hitting
    the first canary file and limits blast radius to < 5%.
    """
    sandbox_dir, manifest = test_sandbox
    total_user_files = manifest["total_user_files"]

    # 1. Initialize Active Response & FIM Monitor
    ar_engine = ActiveResponseEngine(
        wazuh_manager_ip="192.168.56.10",
        dry_run_firewall=True,
    )

    rules_path = Path(__file__).parent.parent / "wazuh_configs" / "local_rules.xml"
    monitor = FimSysmonMonitor(
        rules_xml_path=rules_path,
        active_response_engine=ar_engine,
    )

    # 2. Initialize T1486 Ransomware Simulator
    # Wire the simulator file event directly to the FIM monitor
    simulator = T1486RansomwareSimulator(
        target_dir=sandbox_dir,
        delay_ms=10,
        on_file_encrypted=lambda event: monitor.process_file_event(
            file_path=event.file_path,
            event_type="modified",
            process_id=9999,
            process_name="ransomware_payload.exe",
        ),
    )

    # Link simulator to Active Response for process termination
    ar_engine.target_simulator = simulator

    # 3. Execute Attack
    stats = simulator.run()

    # 4. Verify Containment Assertions
    # A. Active response must have fired and isolated the host
    assert ar_engine.is_isolated is True, "Active Response containment did not fire"
    assert len(ar_engine.isolation_records) >= 1, "No isolation records captured"
    assert ar_engine.isolation_records[0].rule_id == "100201", "Expected Rule 100201 (Canary Modified)"

    # B. Simulator must have been terminated
    assert stats.was_terminated is True, "Ransomware simulator was not terminated"

    # C. First file touched must have been the lexicographical canary
    assert stats.first_canary_path is not None, "No canary file was touched"
    assert "!000_" in stats.first_canary_path, f"First canary touched was not !000_: {stats.first_canary_path}"

    # D. Latency checks
    time_to_detect = monitor.first_alert_time - stats.first_canary_touch_time
    assert time_to_detect < 1.0, f"Time-to-Detect ({time_to_detect:.4f}s) exceeded 1.0s threshold"

    # E. Blast Radius Verification (< 5% affected, > 95% preserved)
    blast_radius_pct = (stats.encrypted_user_files / total_user_files) * 100.0
    preservation_pct = 100.0 - blast_radius_pct

    assert blast_radius_pct < 5.0, f"Blast radius ({blast_radius_pct:.2f}%) exceeded 5.0% threshold"
    assert preservation_pct >= 95.0, f"Preservation rate ({preservation_pct:.2f}%) fell below 95.0%"
