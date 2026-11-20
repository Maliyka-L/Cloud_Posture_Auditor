from auth import get_credential
from collector import get_role_assignments

# Authenticate to Azure
credential = get_credential()

# Get role assignments
roles = get_role_assignments(
    credential
)

print("\nAzure Role Assignments\n")

# No roles found
if not roles:

    print("No role assignments found.")

# Display role assignments
for role in roles:

    print(
        f"Role ID: "
        f"{role['role_definition_id']}"
    )

    print(
        f"Principal ID: "
        f"{role['principal_id']}"
    )

    print("-" * 50)