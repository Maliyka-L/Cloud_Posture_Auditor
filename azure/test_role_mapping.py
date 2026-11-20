from auth import get_credential
from collector import get_role_assignments
from role_mapper import get_role_name

# Authenticate to Azure
credential = get_credential()

# Collect Azure roles
roles = get_role_assignments(
    credential
)

print("\nAzure RBAC Analysis\n")

for role in roles:

    role_name = get_role_name(
        role["role_definition_id"]
    )

    print(
        f"Role: {role_name}"
    )

    print(
        f"Principal ID: "
        f"{role['principal_id']}"
    )

    print("-" * 50)