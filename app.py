from importlib import resources
import json
import traceback
from azure_integration.auth import get_credential
from azure_integration.snapshot_builder import build_snapshot

from datetime import datetime

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

app = Flask(__name__)

latest_findings = []
latest_score = 0
latest_grade = "N/A"


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    global latest_findings
    global latest_score
    global latest_grade

    uploaded_file = request.files.get("snapshot")

    if uploaded_file:

        try:

            data = json.load(uploaded_file)

            findings = run_audit(data)

            risk_score, security_grade = calculate_risk(
                findings
            )

            severity_counts = calculate_severity_counts(
                findings
            )

            latest_findings = findings
            latest_score = risk_score
            latest_grade = security_grade

            # Azure overview statistics
            azure_summary = {

                "resource_groups":
                    len(data.get("resource_groups", [])),

                "storage_accounts":
                    len(data.get("storage_accounts", [])),

                "resources":
                    len(data.get("resources", [])),

                "role_assignments":
                    len(data.get("role_assignments", []))
            }

            return render_template(
                "index.html",
                resources=data,
                findings=findings,
                risk_score=risk_score,
                security_grade=security_grade,
                severity_counts=severity_counts,
                azure_summary=azure_summary,
                scan_time=datetime.now().strftime(
                    "%d/%m/%Y %H:%M:%S"
                )
            )

        except Exception as e:

            return render_template(
                "index.html",
                error=f"Invalid JSON file: {e}"
            )

    return render_template(
        "index.html",
        error="No file uploaded."
    )


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

@app.route("/audit-live")
def audit_live():

    try:

        # Authenticate to Azure
        credential = get_credential()

        # Build Azure snapshot
        snapshot = build_snapshot(
            credential
        )

        # Run audit engine
        findings = run_audit(
            snapshot
        )

        # Calculate risk score
        risk_score, security_grade = (
            calculate_risk(findings)
        )

        # Calculate severity metrics
        severity_counts = (
            calculate_severity_counts(
                findings
            )
        )

        # Azure overview statistics
        azure_summary = {

            "resource_groups":
                len(snapshot.get("resource_groups", [])),

            "storage_accounts":
                len(snapshot.get("storage_accounts", [])),

            "resources":
                len(snapshot.get("resources", [])),

            "role_assignments":
                len(snapshot.get("role_assignments", []))
        }


        return render_template(
            "index.html",
            resources=snapshot,
            findings=findings,
            risk_score=risk_score,
            security_grade=security_grade,
            severity_counts=severity_counts,
            azure_summary=azure_summary,
            scan_time=datetime.now().strftime(
                "%d/%m/%Y %H:%M:%S"
            )
        )

    except Exception as error:
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>"

if __name__ == "__main__":
    app.run(debug=True)