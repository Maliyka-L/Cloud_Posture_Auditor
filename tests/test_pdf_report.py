from pdf_report import generate_pdf_report


def test_pdf_with_no_findings():
    pdf = generate_pdf_report([], 0, "A")
    assert pdf.startswith(b"%PDF")


def test_pdf_with_findings():
    findings = [{
        "severity": "HIGH",
        "title": "Open RDP Port",
        "resource": "web-nsg",
        "recommendation": "Restrict RDP (3389) access.",
        "cis": {
            "framework": "CIS Microsoft Azure Foundations Benchmark",
            "control": "Networking"
        }
    }]

    pdf = generate_pdf_report(findings, 5, "B", "23/11/2026 14:30:00", "live")
    assert pdf.startswith(b"%PDF")
