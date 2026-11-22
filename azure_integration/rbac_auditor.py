# Analyse Azure RBAC assignments
def analyze_roles(roles):

    findings = []

    owner_count = 0

    # Review all collected roles
    for role in roles:

        role_name = role["role_name"]

        # Owner accounts are highly privileged
        if role_name == "Owner":

            owner_count += 1

            findings.append({
                "severity": "HIGH",
                "title": "Privileged Owner Account",
                "description":
                    "Owner role grants complete control over Azure resources."
            })

        # User Access Administrator can grant permissions
        elif role_name == "User Access Administrator":

            findings.append({
                "severity": "MEDIUM",
                "title": "User Access Administrator Detected",
                "description":
                    "This role can manage Azure role assignments."
            })

    # Check for excessive owner accounts
    if owner_count > 1:

        findings.append({
            "severity": "HIGH",
            "title": "Multiple Owner Accounts",
            "description":
                "Consider applying least privilege principles."
        })

    return findings