from azure_integration.auth import get_credential
from azure_integration.collector import get_role_assignments
from azure_integration.guest_checker import mark_guest_users

credential = get_credential()

roles = get_role_assignments(credential)

status = mark_guest_users(credential, roles)

print(f"\nGuest user check: {status}\n")

if status == "skipped":
    print("Your account does not have permission to read directory users.")

for role in roles:
    if "is_guest" in role:
        name = role.get("display_name") or role["principal_id"]
        label = "GUEST" if role["is_guest"] else "Member"
        print(f"[{label}] {name} - {role['role_name']}")
