import json
from flask import Flask, render_template, request

from auditor import run_audit
from scoring import calculate_risk

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    uploaded_file = request.files.get("snapshot")

    if uploaded_file:

        try:
            data = json.load(uploaded_file)

            findings = run_audit(data)

            risk_score, security_grade = calculate_risk(findings)

            return render_template(
                "index.html",
                resources=data,
                findings=findings,
                risk_score=risk_score,
                security_grade=security_grade
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


if __name__ == "__main__":
    app.run(debug=True)