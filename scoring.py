# Calculate risk score and grade from findings
def calculate_risk(findings):

    score = 0

    # Add points for each finding by severity
    for finding in findings:

        if finding["severity"] == "HIGH":
            score += 5

        elif finding["severity"] == "MEDIUM":
            score += 3

        elif finding["severity"] == "LOW":
            score += 1

    # Convert score into a grade
    if score >= 25:
        grade = "F"
    elif score >= 20:
        grade = "D"
    elif score >= 10:
        grade = "C"
    elif score >= 5:
        grade = "B"
    else:
        grade = "A"

    return score, grade