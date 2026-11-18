def calculate_severity_counts(findings):

    high = 0
    medium = 0
    low = 0

    for finding in findings:

        if finding["severity"] == "HIGH":
            high += 1

        elif finding["severity"] == "MEDIUM":
            medium += 1

        elif finding["severity"] == "LOW":
            low += 1

    return {
        "high": high,
        "medium": medium,
        "low": low
    }