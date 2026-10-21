"""
FIM & Sysmon Real-Time Monitor: Simulates Wazuh syscheck (whodata) and Sysmon
kernel file auditing to correlate file modification events against tripwire detection rules.
"""

from dataclasses import dataclass, field
import datetime
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional
import xml.etree.ElementTree as ET

from core.active_response_engine import ActiveResponseEngine


@dataclass
class TripwireAlert:
    rule_id: str
    level: int
    description: str
    mitre_id: str
    file_path: str
    timestamp: float
    iso_time: str
    raw_payload: Dict[str, Any]


class FimSysmonMonitor:
    # Default PCRE2 regex pattern from local_rules.xml
    DEFAULT_CANARY_REGEX = r"(?i)(!000_|#000_|\$000_|_000_)"

    def __init__(
        self,
        rules_xml_path: Optional[Path] = None,
        active_response_engine: Optional[ActiveResponseEngine] = None,
        on_alert_callback: Optional[Callable[[TripwireAlert], None]] = None,
    ):
        self.rules_xml_path = Path(rules_xml_path) if rules_xml_path else None
        self.active_response_engine = active_response_engine
        self.on_alert_callback = on_alert_callback
        self.canary_regex = self._load_canary_regex()
        self.alerts: List[TripwireAlert] = []
        self.first_alert_time: Optional[float] = None
        self.first_canary_touched_time: Optional[float] = None

    def _load_canary_regex(self) -> re.Pattern:
        """Loads and compiles canary matching regex from local_rules.xml if available."""
        if self.rules_xml_path and self.rules_xml_path.exists():
            try:
                tree = ET.parse(self.rules_xml_path)
                root = tree.getroot()
                for rule in root.findall(".//rule"):
                    field_elem = rule.find(".//field[@name='file']")
                    if field_elem is not None and field_elem.text:
                        raw_pattern = field_elem.text.strip()
                        # Normalize (?i) flag for Python re
                        if raw_pattern.startswith("(?i)"):
                            return re.compile(raw_pattern[4:], re.IGNORECASE)
                        return re.compile(raw_pattern)
            except Exception:
                pass
        return re.compile(self.DEFAULT_CANARY_REGEX)

    def process_file_event(
        self,
        file_path: str,
        event_type: str = "modified",
        process_id: Optional[int] = None,
        process_name: str = "python.exe",
    ) -> Optional[TripwireAlert]:
        """
        Processes a file modification, deletion, or creation event.
        Matches against the canary pattern and generates a Level 15 Wazuh alert.
        """
        now = time.perf_counter()
        fname = Path(file_path).name

        # Match against canary regex
        if not self.canary_regex.search(fname):
            return None

        # Record first canary touch timestamp if not set
        if self.first_canary_touched_time is None:
            self.first_canary_touched_time = now

        pid = process_id if process_id is not None else os.getpid()

        # Map event type to Wazuh Rule ID
        if event_type == "deleted":
            rule_id = "100202"
            desc = "CRITICAL: Ransomware canary file deleted - MITRE T1486 Data Encrypted for Impact"
        elif event_type in ["created", "sysmon"]:
            rule_id = "100203"
            desc = "CRITICAL: Sysmon detected canary file creation/overwrite/delete by unauthorized process - MITRE T1486"
        else:
            rule_id = "100201"
            desc = "CRITICAL: Ransomware canary file modified - MITRE T1486 Data Encrypted for Impact"

        iso_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Generate authentic Wazuh Alert JSON structure
        payload = {
            "timestamp": iso_ts,
            "rule": {
                "id": rule_id,
                "level": 15,
                "description": desc,
                "mitre": {"id": ["T1486"]},
            },
            "agent": {
                "id": "001",
                "name": "WIN-LAB-VM-01",
                "ip": "192.168.56.101",
            },
            "data": {
                "audit": {
                    "process_id": pid,
                    "process_name": process_name,
                    "user_id": "S-1-5-21-LABADMIN",
                },
                "syscheck": {
                    "path": file_path,
                    "event": event_type,
                },
                "win": {
                    "eventdata": {
                        "processId": pid,
                        "targetFilename": file_path,
                    }
                },
            },
        }

        alert = TripwireAlert(
            rule_id=rule_id,
            level=15,
            description=desc,
            mitre_id="T1486",
            file_path=file_path,
            timestamp=now,
            iso_time=iso_ts,
            raw_payload=payload,
        )

        self.alerts.append(alert)
        if self.first_alert_time is None:
            self.first_alert_time = now

        # Notify callback
        if self.on_alert_callback:
            self.on_alert_callback(alert)

        # Trigger Active Response immediately
        if self.active_response_engine:
            self.active_response_engine.trigger_containment(payload)

        return alert
