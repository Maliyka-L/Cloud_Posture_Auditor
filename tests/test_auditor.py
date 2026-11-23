import json
from pathlib import Path

from auditor import run_audit

# Path to the sample snapshot
SAMPLE = Path(__file__).parent.parent / "sample_data" / "azure_snapshot.json"


# Load the sample snapshot
def load_sample():
    with open(SAMPLE) as file:
        return json.load(file)


# Get finding titles
def titles(findings):
    return [finding["title"] for finding in findings]


# Sample snapshot finds every issue
def test_sample_snapshot_findings():
    findings = run_audit(load_sample())

    assert titles(findings).count("Public Storage Account") == 1
    assert "Storage Encryption Disabled" in titles(findings)
    assert "Secure Transfer Not Required" in titles(findings)
    assert "Outdated TLS Version" in titles(findings)
    assert "Open RDP Port" in titles(findings)
    assert "Open SSH Port" in titles(findings)
    assert "Guest User With Owner Access" in titles(findings)
    assert "User Access Administrator Detected" in titles(findings)


# Empty snapshot has no findings
def test_empty_snapshot_has_no_findings():
    assert run_audit({}) == []


# Secure storage account has no findings
def test_secure_storage_has_no_findings():
    snapshot = {
        "storage_accounts": [{
            "name": "securestore",
            "public_access": False,
            "encrypted": True,
            "https_only": True,
            "minimum_tls_version": "TLS1_2"
        }]
    }

    assert run_audit(snapshot) == []


# More than 3 Owners is flagged
def test_too_many_owners():
    snapshot = {
        "role_assignments": [
            {"role_name": "Owner", "principal_id": f"user{i}"}
            for i in range(4)
        ]
    }

    assert "Too Many Owners" in titles(run_audit(snapshot))


# 3 Owners is allowed
def test_three_owners_is_allowed():
    snapshot = {
        "role_assignments": [
            {"role_name": "Owner", "principal_id": f"user{i}"}
            for i in range(3)
        ]
    }

    assert "Too Many Owners" not in titles(run_audit(snapshot))


# Every finding has a CIS mapping
def test_findings_have_cis_mapping():
    for finding in run_audit(load_sample()):
        assert finding["cis"]["framework"] != "Not Mapped"
