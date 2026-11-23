FRAMEWORK = "CIS Microsoft Azure Foundations Benchmark"

CIS_MAPPINGS = {

    "Public Storage Account": "Storage Accounts",
    "Storage Encryption Disabled": "Storage Accounts",
    "Secure Transfer Not Required": "Storage Accounts",
    "Outdated TLS Version": "Storage Accounts",

    "Open RDP Port": "Networking",
    "Open SSH Port": "Networking",

    "Privileged Owner Account": "Identity and Access Management",
    "Guest User With Owner Access": "Identity and Access Management",
    "Guest User With Azure Access": "Identity and Access Management",
    "Too Many Owners": "Identity and Access Management",
    "User Access Administrator Detected": "Identity and Access Management"
}


# Return CIS mapping information for a finding
def get_cis_mapping(finding_title):

    control = CIS_MAPPINGS.get(finding_title)

    if not control:
        return {
            "framework": "Not Mapped",
            "control": "Not Mapped"
        }

    return {
        "framework": FRAMEWORK,
        "control": control
    }
