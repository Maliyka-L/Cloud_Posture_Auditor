from auth import get_credential
from collector import get_role_assignments
from role_mapper import get_role_name
from rbac_auditor import analyze_roles

# Authenticate to Azure
credential = get_credential()

# Collect Azure roles
roles = get_role_assignments(
    credential
)

mapped_roles = []

print("\nAzure RBAC Analysis\n")

# Map Azure role IDs to names
for role in roles:

    role_name = get_role_name(
        role["role_definition_id"]
    )

    mapped_roles.append({
        "role_name": role_name
    })

    print(
        f"Role: {role_name}"
    )

print("\nSecurity Findings\n")

# Analyse collected roles
findings = analyze_roles(
    mapped_roles
)

# Display findings
for finding in findings:

    print(
        f"[{finding['severity']}] "
        f"{finding['title']}"
    )

    print(
        finding["description"]
    )

    print("-" * 50)