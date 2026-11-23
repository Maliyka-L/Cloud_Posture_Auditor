# Build the text audit report
def generate_report(findings, risk_score, security_grade):

    report = []

    # Report header
    report.append("AZUREGUARD SECURITY AUDIT REPORT")
    report.append("=" * 50)

    report.append(f"Risk Score: {risk_score}")
    report.append(f"Security Grade: {security_grade}")
    report.append(f"Total Findings: {len(findings)}")
    report.append("")

    # Findings section
    report.append("FINDINGS")
    report.append("-" * 50)

    if not findings:
        report.append("No security findings detected.")

    # Add each finding
    for finding in findings:

        report.append(f"Title: {finding['title']}")
        report.append(f"Severity: {finding['severity']}")
        report.append(f"Resource: {finding['resource']}")
        report.append(f"Recommendation: {finding['recommendation']}")

        # Add the CIS benchmark if mapped
        cis = finding.get("cis")

        if cis and cis["framework"] != "Not Mapped":
            report.append(f"Benchmark: {cis['framework']} - {cis['control']}")

        report.append("")

    return "\n".join(report)
