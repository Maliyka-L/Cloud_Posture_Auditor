from azure_integration.auth import get_credential
from azure_integration.collector import get_network_security_groups

# Authenticate to Azure
credential = get_credential()

# Get network security groups
nsgs = get_network_security_groups(credential)

print("\nNetwork Security Groups:\n")

# No NSGs found
if not nsgs:
    print("No network security groups found.")

# Display NSGs and open ports
for nsg in nsgs:
    print(f"{nsg['name']} ({nsg['location']}) - {nsg['rule_count']} rules")
    print(f"  RDP open to internet: {nsg['open_rdp']}")
    print(f"  SSH open to internet: {nsg['open_ssh']}")
