from auth import get_credential
from collector import get_resources

credential = get_credential()

resources = get_resources(credential)

print("\nResources:\n")

if not resources:
    print("No resources found.")

for resource in resources:

    print(
        f"{resource['name']} | "
        f"{resource['type']} | "
        f"{resource['location']}"
    )