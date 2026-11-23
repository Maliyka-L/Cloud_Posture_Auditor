from azure_integration.auth import get_credential
from azure_integration.collector import get_resource_groups

# Authenticate to Azure
credential = get_credential()

# Get resource groups
groups = get_resource_groups(credential)

print("\nResource Groups:\n")

# No resource groups found
if not groups:
    print("No resource groups found.")

# Display resource groups
for group in groups:
    print(f"{group['name']} ({group['location']})")
