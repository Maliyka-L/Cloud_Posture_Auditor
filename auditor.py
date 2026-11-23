from azure_integration.rbac_auditor import analyze_roles, MAX_OWNERS
from azure_integration.cis_mapper import get_cis_mapping

# TLS versions that are no longer secure
WEAK_TLS_VERSIONS = ("TLS1_0", "TLS1_1")


# Storage Checks
def check_storage(snapshot):

    findings = []

    for storage in snapshot.get("storage_accounts", []):

        name = storage.get("name", "Unknown storage account")

        # Public blob access
        if storage.get("public_access"):
            findings.append({
                "severity": "HIGH",
                "title": "Public Storage Account",
                "resource": name,
                "recommendation": "Disable public blob access."
            })

        # Encryption disabled
        if not storage.get("encrypted", True):
            findings.append({
                "severity": "MEDIUM",
                "title": "Storage Encryption Disabled",
                "resource": name,
                "recommendation": "Enable encryption."
            })

        # HTTPS not required
        if storage.get("https_only") is False:
            findings.append({
                "severity": "MEDIUM",
                "title": "Secure Transfer Not Required",
                "resource": name,
                "recommendation": "Enable 'Secure transfer required' (HTTPS only)."
            })

        # Outdated TLS version
        if storage.get("minimum_tls_version") in WEAK_TLS_VERSIONS:
            findings.append({
                "severity": "MEDIUM",
                "title": "Outdated TLS Version",
                "resource": name,
                "recommendation": "Set the minimum TLS version to TLS 1.2."
            })

    return findings


# Network Checks
def check_network(snapshot):

    findings = []

    for nsg in snapshot.get("network_security_groups", []):

        name = nsg.get("name", "Unknown NSG")

        # RDP open to the internet
        if nsg.get("open_rdp"):
            findings.append({
                "severity": "HIGH",
                "title": "Open RDP Port",
                "resource": name,
                "recommendation": "Restrict RDP (3389) access."
            })

        # SSH open to the internet
        if nsg.get("open_ssh"):
            findings.append({
                "severity": "HIGH",
                "title": "Open SSH Port",
                "resource": name,
                "recommendation": "Restrict SSH (22) access."
            })

    return findings


# IAM Checks (users from uploaded snapshots)
def check_users(snapshot):

    findings = []

    owner_count = 0

    for user in snapshot.get("users", []):

        name = user.get("name", "Unknown user")

        # Only Owners are checked
        if user.get("role") != "Owner":
            continue

        owner_count += 1

        # Guest with Owner access
        if user.get("guest"):
            findings.append({
                "severity": "HIGH",
                "title": "Guest User With Owner Access",
                "resource": name,
                "recommendation": "Remove privileged guest access."
            })
        else:
            findings.append({
                "severity": "HIGH",
                "title": "Privileged Owner Account",
                "resource": name,
                "recommendation": "Review Owner permissions."
            })

    # Check for too many Owners
    if owner_count > MAX_OWNERS:
        findings.append({
            "severity": "MEDIUM",
            "title": "Too Many Owners",
            "resource": "Azure Subscription",
            "recommendation":
                f"Keep {MAX_OWNERS} or fewer Owners and apply least privilege."
        })

    return findings


# Run every check on a snapshot
def run_audit(snapshot):

    findings = []

    findings += check_storage(snapshot)
    findings += check_network(snapshot)
    findings += check_users(snapshot)
    findings += analyze_roles(snapshot.get("role_assignments", []))

    # Add the CIS mapping to each finding
    for finding in findings:
        finding["cis"] = get_cis_mapping(finding["title"])

    return findings
