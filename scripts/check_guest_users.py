from azure_integration.auth import get_credential
from azure_integration.collector import get_role_assignments
from azure_integration.guest_checker import mark_guest_users

# Authenticate to Azure
credential = get_credential()

# Get role assignments
roles = get_role_assignments(credential)

# Check for guest users
status = mark_guest_users(credential, roles)

print(f"\nGuest user check: {status}\n")

# No directory permission
if status == "skipped":
    print("Your account does not have permission to read directory users.")

# Display users and their roles
for role in roles:
    if "is_guest" in role:
        name = role.get("display_name") or role["principal_id"]
        label = "GUEST" if role["is_guest"] else "Member"
        print(f"[{label}] {name} - {role['role_name']}")
