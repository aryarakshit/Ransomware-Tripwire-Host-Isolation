"""
Unit tests validating Wazuh and Sysmon XML detection rules for the Ransomware Tripwire.
"""

from pathlib import Path
import re
import xml.etree.ElementTree as ET
import pytest

CONFIG_DIR = Path(__file__).parent.parent / "wazuh_configs"
LOCAL_RULES_PATH = CONFIG_DIR / "local_rules.xml"
SYSMON_CONFIG_PATH = CONFIG_DIR / "sysmon_canary_config.xml"
OSSEC_CONF_PATH = CONFIG_DIR / "ossec_fim_whodata.conf"


def test_local_rules_xml_well_formed():
    """Verify local_rules.xml parses cleanly with xml.etree.ElementTree."""
    assert LOCAL_RULES_PATH.exists(), f"{LOCAL_RULES_PATH} does not exist"
    tree = ET.parse(LOCAL_RULES_PATH)
    root = tree.getroot()
    assert root.tag == "group"
    assert "tripwire" in root.attrib.get("name", "")


def test_sysmon_xml_well_formed():
    """Verify sysmon_canary_config.xml parses cleanly with xml.etree.ElementTree."""
    assert SYSMON_CONFIG_PATH.exists(), f"{SYSMON_CONFIG_PATH} does not exist"
    tree = ET.parse(SYSMON_CONFIG_PATH)
    root = tree.getroot()
    assert root.tag == "Sysmon"
    assert root.attrib.get("schemaversion") == "4.90"


def test_ossec_fim_conf_well_formed():
    """Verify ossec_fim_whodata.conf is well-formed XML with syscheck whodata and active-response."""
    assert OSSEC_CONF_PATH.exists(), f"{OSSEC_CONF_PATH} does not exist"
    tree = ET.parse(OSSEC_CONF_PATH)
    root = tree.getroot()
    assert root.tag == "ossec_config"

    # Verify syscheck whodata is enabled
    whodata_dirs = root.findall(".//directories[@whodata='yes']")
    assert len(whodata_dirs) >= 4, "Expected at least 4 monitored whodata directories"

    # Verify active response binding
    ar = root.find(".//active-response")
    assert ar is not None
    assert ar.find("command").text == "isolate-ransomware-host"
    assert "100201" in ar.find("rules_id").text


def test_wazuh_rule_definitions():
    """Validate specific rule IDs, severity levels, and MITRE T1486 mappings."""
    tree = ET.parse(LOCAL_RULES_PATH)
    root = tree.getroot()
    rules = {r.attrib["id"]: r for r in root.findall(".//rule")}

    # Rule 100201: Canary Modified
    assert "100201" in rules
    r100201 = rules["100201"]
    assert r100201.attrib["level"] == "15"
    assert r100201.find("if_sid").text == "550"
    assert r100201.find("mitre/id").text == "T1486"

    # Rule 100202: Canary Deleted
    assert "100202" in rules
    r100202 = rules["100202"]
    assert r100202.attrib["level"] == "15"
    assert r100202.find("if_sid").text == "553"
    assert r100202.find("mitre/id").text == "T1486"

    # Rule 100203: Sysmon File Event
    assert "100203" in rules
    r100203 = rules["100203"]
    assert r100203.attrib["level"] == "15"
    assert r100203.find("mitre/id").text == "T1486"

    # Rule 100204: Active Response Containment Success
    assert "100204" in rules
    r100204 = rules["100204"]
    assert r100204.attrib["level"] == "12"


def test_canary_regex_accuracy():
    """Verify PCRE2 regex correctly matches all canary formats and rejects regular user files."""
    tree = ET.parse(LOCAL_RULES_PATH)
    rule_100201 = tree.find(".//rule[@id='100201']")
    pattern_text = rule_100201.find("field").text.strip()

    # Normalize (?i) for python re
    clean_pattern = pattern_text[4:] if pattern_text.startswith("(?i)") else pattern_text
    compiled_re = re.compile(clean_pattern, re.IGNORECASE)

    # Positive test cases (must match)
    canaries = [
        "!000_CONFIDENTIAL_Payroll_2026.xlsx",
        "#000_AWS_Production_Root_Keys.txt",
        "$000_Executive_M&A_Targets.docx",
        "_000_Backup_Recovery_Seeds.pdf",
        "C:\\Users\\LabAdmin\\Documents\\!000_CONFIDENTIAL_Payroll_2026.xlsx",
        "C:\\Shares\\Finance_Records\\#000_AWS_Production_Root_Keys.txt",
    ]
    for canary in canaries:
        assert compiled_re.search(canary) is not None, f"Regex failed to match canary: {canary}"

    # Negative test cases (must NOT match)
    user_files = [
        "Account_Statement_001.pdf",
        "Budget_Forecast_2026.xlsx",
        "Customer_Ledger_99.csv",
        "Invoice_001.pdf",
        "Normal_User_Doc.docx",
        "Employee_Handbook.docx",
    ]
    for user_file in user_files:
        assert compiled_re.search(user_file) is None, f"Regex incorrectly matched user file: {user_file}"


def test_sysmon_canary_targets():
    """Verify Sysmon event rules contain target filters for all canary prefixes."""
    tree = ET.parse(SYSMON_CONFIG_PATH)
    root = tree.getroot()

    target_filenames = [elem.text for elem in root.findall(".//TargetFilename")]
    required_prefixes = ["!000_", "#000_", "$000_", "_000_"]

    for prefix in required_prefixes:
        assert prefix in target_filenames, f"Prefix {prefix} missing from Sysmon TargetFilename rules"
