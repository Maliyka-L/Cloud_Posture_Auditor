from azure_integration.auth import get_credential
from azure_integration.collector import get_storage_accounts

credential = get_credential()

accounts = get_storage_accounts(credential)

print("\nStorage Accounts:\n")

if not accounts:
    print("No storage accounts found.")

for account in accounts:
    print(f"{account['name']} ({account['location']})")
    print(f"  Public access: {account['public_access']}")
    print(f"  HTTPS only: {account['https_only']}")
    print(f"  Minimum TLS: {account['minimum_tls_version']}")
