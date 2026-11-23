from azure_integration.auth import get_credential
from azure_integration.collector import get_storage_accounts

# Authenticate to Azure
credential = get_credential()

# Get storage accounts
accounts = get_storage_accounts(credential)

print("\nStorage Accounts:\n")

# No storage accounts found
if not accounts:
    print("No storage accounts found.")

# Display storage accounts and their security settings
for account in accounts:
    print(f"{account['name']} ({account['location']})")
    print(f"  Public access: {account['public_access']}")
    print(f"  HTTPS only: {account['https_only']}")
    print(f"  Minimum TLS: {account['minimum_tls_version']}")
