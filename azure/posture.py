# Calculate overall Azure posture score
def calculate_posture(snapshot):

    score = 100

    findings = []

    # Check for missing storage accounts
    if len(snapshot["storage_accounts"]) == 0:

        score -= 10

        findings.append(
            "No storage accounts detected."
        )

    # Check for missing network security groups
    if len(snapshot["network_security_groups"]) == 0:

        score -= 15

        findings.append(
            "No network security groups detected."
        )

    # Check if no resources exist
    if len(snapshot["resources"]) == 0:

        score -= 5

        findings.append(
            "No Azure resources detected."
        )

    return {
        "score": score,
        "findings": findings
    }