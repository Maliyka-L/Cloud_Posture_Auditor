def run_audit(snapshot):

    findings = []

    # Storage Checks
    for storage in snapshot.get("storage_accounts", []):

        if storage.get("public_access"):
            findings.append({
                "severity": "HIGH",
                "title": "Public Storage Account",
                "resource": storage["name"],
                "recommendation": "Disable public access."
            })

        if not storage.get("encrypted", True):
            findings.append({
                "severity": "MEDIUM",
                "title": "Storage Encryption Disabled",
                "resource": storage["name"],
                "recommendation": "Enable encryption."
            })

    # Network Checks
    for nsg in snapshot.get("network_security_groups", []):

        if nsg.get("open_rdp"):
            findings.append({
                "severity": "HIGH",
                "title": "Open RDP Port",
                "resource": nsg["name"],
                "recommendation": "Restrict RDP access."
            })

        if nsg.get("open_ssh"):
            findings.append({
                "severity": "HIGH",
                "title": "Open SSH Port",
                "resource": nsg["name"],
                "recommendation": "Restrict SSH access."
            })

    # IAM Checks
    owner_count = 0

    for user in snapshot.get("users", []):

        if user.get("role") == "Owner":
            owner_count += 1

            findings.append({
                "severity": "HIGH",
                "title": "Privileged Owner Account",
                "resource": user["name"],
                "recommendation": "Review Owner permissions."
            })

        if user.get("guest") and user.get("role") == "Owner":
            findings.append({
                "severity": "HIGH",
                "title": "Guest User With Owner Access",
                "resource": user["name"],
                "recommendation": "Remove privileged guest access."
            })

    if owner_count > 2:
        findings.append({
            "severity": "MEDIUM",
            "title": "Too Many Owners",
            "resource": "Azure Subscription",
            "recommendation": "Apply least privilege principles."
        })

    return findings