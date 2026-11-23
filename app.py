import json
import os
import traceback
from datetime import datetime

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    Response
)

from auditor import run_audit
from scoring import calculate_risk
from analytics import calculate_severity_counts
from report_generator import generate_report
from pdf_report import generate_pdf_report

load_dotenv()

app = Flask(__name__)

latest_findings = []
latest_score = 0
latest_grade = "N/A"
latest_scan_time = ""
latest_source = ""


def build_dashboard(snapshot, source):

    global latest_findings
    global latest_score
    global latest_grade
    global latest_scan_time
    global latest_source

    findings = run_audit(snapshot)

    risk_score, security_grade = calculate_risk(findings)

    severity_counts = calculate_severity_counts(findings)

    latest_findings = findings
    latest_score = risk_score
    latest_grade = security_grade
    latest_scan_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    latest_source = source

    azure_summary = {
        "resource_groups": len(snapshot.get("resource_groups", [])),
        "storage_accounts": len(snapshot.get("storage_accounts", [])),
        "resources": len(snapshot.get("resources", [])),
        "role_assignments": len(snapshot.get("role_assignments", [])),
        "network_security_groups":
            len(snapshot.get("network_security_groups", []))
    }

    resources_scanned = (
        len(snapshot.get("storage_accounts", []))
        + len(snapshot.get("network_security_groups", []))
        + len(snapshot.get("users", []))
        + len(snapshot.get("role_assignments", []))
    )

    return render_template(
        "index.html",
        scanned=True,
        source=source,
        findings=findings,
        risk_score=risk_score,
        security_grade=security_grade,
        severity_counts=severity_counts,
        azure_summary=azure_summary,
        resources_scanned=resources_scanned,
        guest_check=snapshot.get("guest_check"),
        scan_time=latest_scan_time
    )


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    uploaded_file = request.files.get("snapshot")

    if not uploaded_file:
        return render_template("index.html", error="No file uploaded.")

    try:
        data = json.load(uploaded_file)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return render_template(
            "index.html",
            error="That file is not valid JSON."
        )

    if not isinstance(data, dict):
        return render_template(
            "index.html",
            error="The snapshot must be a JSON object."
        )

    return build_dashboard(data, source="upload")


@app.route("/audit-live")
def audit_live():

    try:
        from azure_integration.auth import get_credential
        from azure_integration.snapshot_builder import build_snapshot

        credential = get_credential()
        snapshot = build_snapshot(credential)

    except Exception:
        traceback.print_exc()
        return render_template(
            "index.html",
            error="Could not connect to Azure. "
                  "Check your sign-in and AZURE_SUBSCRIPTION_ID, "
                  "then try again."
        )

    return build_dashboard(snapshot, source="live")


@app.route("/download-report")
def download_report():

    report = generate_report(
        latest_findings,
        latest_score,
        latest_grade
    )

    return Response(
        report,
        mimetype="text/plain",
        headers={
            "Content-Disposition":
            "attachment; filename=azureguard_report.txt"
        }
    )


@app.route("/download-pdf")
def download_pdf():

    pdf = generate_pdf_report(
        latest_findings,
        latest_score,
        latest_grade,
        scan_time=latest_scan_time,
        source=latest_source
    )

    return Response(
        pdf,
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=azureguard_report.pdf"
        }
    )


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")
