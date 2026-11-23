from azure_integration.auth import get_credential
from azure_integration.snapshot_builder import build_snapshot
from auditor import run_audit

# Authenticate to Azure
credential = get_credential()

# Build live Azure snapshot
snapshot = build_snapshot(credential)

# Run audit engine
findings = run_audit(snapshot)

print("\nFindings:\n")

# No findings
if not findings:
    print("No security findings detected.")

# Display findings
for finding in findings:
    print(f"[{finding['severity']}] {finding['title']} - {finding['resource']}")
