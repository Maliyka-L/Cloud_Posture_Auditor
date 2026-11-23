MAX_OWNERS = 3


# Analyse Azure RBAC role assignments
def analyze_roles(roles):

    findings = []

    owner_count = 0

    for role in roles:

        role_name = role.get("role_name", "Unknown Role")
        principal = (
            role.get("display_name")
            or role.get("principal_id")
            or "Unknown principal"
        )
        guest = role.get("is_guest", False)

        if role_name == "Owner":
            owner_count += 1

        if guest and role_name == "Owner":

            findings.append({
                "severity": "HIGH",
                "title": "Guest User With Owner Access",
                "resource": principal,
                "recommendation":
                    "Remove Owner access from external guest accounts."
            })

        elif guest:

            findings.append({
                "severity": "MEDIUM",
                "title": "Guest User With Azure Access",
                "resource": principal,
                "recommendation":
                    f"Check this guest still needs the {role_name} role."
            })

        if role_name == "Owner" and not guest:

            findings.append({
                "severity": "HIGH",
                "title": "Privileged Owner Account",
                "resource": principal,
                "recommendation":
                    "Owner grants full control. Review whether this "
                    "account needs Owner or a lower role."
            })

        elif role_name == "User Access Administrator" and not guest:

            findings.append({
                "severity": "MEDIUM",
                "title": "User Access Administrator Detected",
                "resource": principal,
                "recommendation":
                    "This role can grant access to others. "
                    "Limit it to accounts that need it."
            })

    if owner_count > MAX_OWNERS:

        findings.append({
            "severity": "MEDIUM",
            "title": "Too Many Owners",
            "resource": "Azure Subscription",
            "recommendation":
                f"Keep {MAX_OWNERS} or fewer Owners and apply "
                "least privilege."
        })

    return findings
