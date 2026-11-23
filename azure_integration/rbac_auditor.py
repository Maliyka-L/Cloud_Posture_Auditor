# Most Owners a subscription should have
MAX_OWNERS = 3


# Analyse Azure RBAC role assignments
def analyze_roles(roles):

    findings = []

    owner_count = 0

    # Review all collected roles
    for role in roles:

        role_name = role.get("role_name", "Unknown Role")
        principal = (
            role.get("display_name")
            or role.get("principal_id")
            or "Unknown principal"
        )
        guest = role.get("is_guest", False)

        # Count Owners
        if role_name == "Owner":
            owner_count += 1

        # Guest with Owner access
        if guest and role_name == "Owner":

            findings.append({
                "severity": "HIGH",
                "title": "Guest User With Owner Access",
                "resource": principal,
                "recommendation":
                    "Remove Owner access from external guest accounts."
            })

        # Guest with any other role
        elif guest:

            findings.append({
                "severity": "MEDIUM",
                "title": "Guest User With Azure Access",
                "resource": principal,
                "recommendation":
                    f"Check this guest still needs the {role_name} role."
            })

        # Owner accounts are highly privileged
        if role_name == "Owner" and not guest:

            findings.append({
                "severity": "HIGH",
                "title": "Privileged Owner Account",
                "resource": principal,
                "recommendation":
                    "Owner grants full control. Review whether this "
                    "account needs Owner or a lower role."
            })

        # User Access Administrator can grant permissions
        elif role_name == "User Access Administrator" and not guest:

            findings.append({
                "severity": "MEDIUM",
                "title": "User Access Administrator Detected",
                "resource": principal,
                "recommendation":
                    "This role can grant access to others. "
                    "Limit it to accounts that need it."
            })

    # Check for too many Owners
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
