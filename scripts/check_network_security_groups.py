from azure_integration.auth import get_credential
from azure_integration.collector import get_network_security_groups

credential = get_credential()

nsgs = get_network_security_groups(credential)

print("\nNetwork Security Groups:\n")

if not nsgs:
    print("No network security groups found.")

for nsg in nsgs:
    print(f"{nsg['name']} ({nsg['location']}) - {nsg['rule_count']} rules")
    print(f"  RDP open to internet: {nsg['open_rdp']}")
    print(f"  SSH open to internet: {nsg['open_ssh']}")
