from azure_integration.auth import get_credential
from azure_integration.snapshot_builder import build_snapshot
from auditor import run_audit

credential = get_credential()

snapshot = build_snapshot(credential)

findings = run_audit(snapshot)

print("\nFindings:\n")

if not findings:
    print("No security findings detected.")

for finding in findings:
    print(f"[{finding['severity']}] {finding['title']} - {finding['resource']}")
