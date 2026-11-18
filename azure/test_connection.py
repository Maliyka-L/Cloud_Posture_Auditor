from auth import get_credential
from collector import get_resource_groups

credential = get_credential()

groups = get_resource_groups(credential)

print("\nResource Groups:\n")

for group in groups:

    print(
        f"{group['name']} ({group['location']})"
    )