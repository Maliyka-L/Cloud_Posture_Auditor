def generate_report(findings, risk_score, security_grade):

    report = []

    report.append("AZUREGUARD SECURITY AUDIT REPORT")
    report.append("=" * 50)

    report.append(f"Risk Score: {risk_score}")
    report.append(f"Security Grade: {security_grade}")
    report.append("")

    report.append("FINDINGS")
    report.append("-" * 50)

    for finding in findings:

        report.append(f"Title: {finding['title']}")
        report.append(f"Severity: {finding['severity']}")
        report.append(f"Resource: {finding['resource']}")
        report.append(f"Recommendation: {finding['recommendation']}")
        report.append("")

    return "\n".join(report)













