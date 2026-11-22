from auth import get_credential
from collector import get_role_assignments
from role_mapper import get_role_name
from rbac_auditor import analyze_roles
from cis_mapper import get_cis_mapping

# Authenticate to Azure
credential = get_credential()

# Collect Azure roles
roles = get_role_assignments(
    credential
)

mapped_roles = []

# Convert role IDs into names
for role in roles:

    role_name = get_role_name(
        role["role_definition_id"]
    )

    mapped_roles.append({
        "role_name": role_name
    })

# Generate security findings
findings = analyze_roles(
    mapped_roles
)

print("\nAzure Security Findings\n")

# Display findings and framework mappings
for finding in findings:

    cis = get_cis_mapping(
        finding["title"]
    )

    print(
        f"[{finding['severity']}] "
        f"{finding['title']}"
    )

    print(
        finding["description"]
    )

    print(
        f"Framework: "
        f"{cis['framework']}"
    )

    print(
        f"Control: "
        f"{cis['control']}"
    )

    print("-" * 50)