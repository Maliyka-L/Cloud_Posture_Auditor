from auth import get_credential
from collector import get_storage_accounts

credential = get_credential()

accounts = get_storage_accounts(credential)

print("\nStorage Accounts:\n")

if not accounts:
    print("No storage accounts found.")

for account in accounts:

    print(
        f"{account['name']} ({account['location']})"
    )