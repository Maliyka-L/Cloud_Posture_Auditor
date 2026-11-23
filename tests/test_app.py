import io
from pathlib import Path

from app import app

# Path to the sample snapshot
SAMPLE = Path(__file__).parent.parent / "sample_data" / "azure_snapshot.json"


# Flask test client
def client():
    app.config["TESTING"] = True
    return app.test_client()


# Dashboard page loads
def test_dashboard_loads():
    response = client().get("/")
    assert response.status_code == 200
    assert b"AzureGuard" in response.data


# Uploading the sample snapshot shows findings
def test_upload_sample_snapshot():
    with open(SAMPLE, "rb") as file:
        response = client().post(
            "/upload",
            data={"snapshot": (file, "azure_snapshot.json")},
            content_type="multipart/form-data"
        )

    assert response.status_code == 200
    assert b"Public Storage Account" in response.data
    assert b"Uploaded snapshot" in response.data


# Invalid JSON shows an error
def test_upload_invalid_json():
    response = client().post(
        "/upload",
        data={"snapshot": (io.BytesIO(b"not json"), "bad.json")},
        content_type="multipart/form-data"
    )

    assert b"not valid JSON" in response.data


# Text report downloads
def test_download_report():
    test_client = client()

    with open(SAMPLE, "rb") as file:
        test_client.post(
            "/upload",
            data={"snapshot": (file, "azure_snapshot.json")},
            content_type="multipart/form-data"
        )

    response = test_client.get("/download-report")
    assert b"AZUREGUARD SECURITY AUDIT REPORT" in response.data


# PDF report downloads
def test_download_pdf_report():
    test_client = client()

    with open(SAMPLE, "rb") as file:
        test_client.post(
            "/upload",
            data={"snapshot": (file, "azure_snapshot.json")},
            content_type="multipart/form-data"
        )

    response = test_client.get("/download-pdf")
    assert response.mimetype == "application/pdf"
    assert response.data.startswith(b"%PDF")
