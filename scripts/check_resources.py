from azure_integration.auth import get_credential
from azure_integration.collector import get_resources

# Authenticate to Azure
credential = get_credential()

# Get resources
resources = get_resources(credential)

print("\nResources:\n")

# No resources found
if not resources:
    print("No resources found.")

# Display resources
for resource in resources:
    print(f"{resource['name']} | {resource['type']} | {resource['location']}")
