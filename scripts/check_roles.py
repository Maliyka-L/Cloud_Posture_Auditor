from azure_integration.auth import get_credential
from azure_integration.collector import get_role_assignments

# Authenticate to Azure
credential = get_credential()

# Get role assignments
roles = get_role_assignments(credential)

print("\nAzure Role Assignments\n")

# No roles found
if not roles:
    print("No role assignments found.")

# Display role assignments
for role in roles:
    print(f"Role: {role['role_name']}")
    print(f"Principal ID: {role['principal_id']}")
    print(f"Principal type: {role['principal_type']}")
    print("-" * 50)
