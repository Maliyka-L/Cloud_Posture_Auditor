from azure_integration.auth import get_credential
from azure_integration.collector import get_role_assignments
from azure_integration.rbac_auditor import analyze_roles
from azure_integration.cis_mapper import get_cis_mapping

credential = get_credential()

roles = get_role_assignments(credential)

findings = analyze_roles(roles)

print("\nAzure RBAC Findings\n")

if not findings:
    print("No RBAC findings detected.")

for finding in findings:
    cis = get_cis_mapping(finding["title"])

    print(f"[{finding['severity']}] {finding['title']}")
    print(f"Resource: {finding['resource']}")
    print(finding["recommendation"])
    print(f"Benchmark: {cis['framework']} - {cis['control']}")
    print("-" * 50)
