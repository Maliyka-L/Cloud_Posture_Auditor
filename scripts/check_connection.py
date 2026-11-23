from azure_integration.auth import get_credential
from azure_integration.collector import get_resource_groups

credential = get_credential()

groups = get_resource_groups(credential)

print("\nResource Groups:\n")

if not groups:
    print("No resource groups found.")

for group in groups:
    print(f"{group['name']} ({group['location']})")
