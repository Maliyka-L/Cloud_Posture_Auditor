import os

from dotenv import load_dotenv
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.network import NetworkManagementClient

from azure_integration.role_mapper import get_role_name
from azure_integration.nsg_rules import analyze_nsg

# Load settings from .env
load_dotenv()


# Get the subscription ID from .env
def get_subscription_id():

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    if not subscription_id:
        raise ValueError(
            "AZURE_SUBSCRIPTION_ID is not set. Add it to your .env file."
        )

    return subscription_id


# Collect Azure Resource Groups
def get_resource_groups(credential):

    # Create Resource Management client
    client = ResourceManagementClient(
        credential,
        get_subscription_id()
    )

    # Store discovered resource groups
    groups = []

    # Loop through resource groups
    for group in client.resource_groups.list():

        groups.append({
            "name": group.name,
            "location": group.location
        })

    return groups


# Collect Azure Storage Accounts and their security settings
def get_storage_accounts(credential):

    # Create Storage Management client
    client = StorageManagementClient(
        credential,
        get_subscription_id()
    )

    # Store storage accounts
    accounts = []

    # Loop through storage accounts and record their security settings
    for account in client.storage_accounts.list():

        accounts.append({
            "name": account.name,
            "location": account.location,
            "public_access": bool(account.allow_blob_public_access),
            "encrypted": account.encryption is not None,
            "https_only": bool(account.enable_https_traffic_only),
            "minimum_tls_version": account.minimum_tls_version
        })

    return accounts


# Collect Azure Resources
def get_resources(credential):

    # Create Resource Management client
    client = ResourceManagementClient(
        credential,
        get_subscription_id()
    )

    # Store Azure resources
    resources = []

    # Loop through resources
    for resource in client.resources.list():

        resources.append({
            "name": resource.name,
            "type": resource.type,
            "location": resource.location
        })

    return resources


# Collect Azure RBAC Role Assignments
def get_role_assignments(credential):

    # Create Authorization client
    client = AuthorizationManagementClient(
        credential,
        get_subscription_id()
    )

    # Store role assignments
    roles = []

    # Loop through subscription role assignments
    for assignment in client.role_assignments.list_for_subscription():

        roles.append({
            "role_definition_id": assignment.role_definition_id,
            "role_name": get_role_name(assignment.role_definition_id),
            "principal_id": assignment.principal_id,
            "principal_type": getattr(assignment, "principal_type", None)
        })

    return roles


# Collect Network Security Groups and check their inbound rules
def get_network_security_groups(credential):

    # Create Network Management client
    client = NetworkManagementClient(
        credential,
        get_subscription_id()
    )

    # Store network security groups
    nsgs = []

    # Loop through network security groups
    for nsg in client.network_security_groups.list_all():

        # Store this NSG's security rules
        rules = []

        # Loop through each security rule
        for rule in nsg.security_rules or []:

            rules.append({
                "name": rule.name,
                "direction": rule.direction,
                "access": rule.access,
                "source_address_prefix": rule.source_address_prefix,
                "source_address_prefixes": rule.source_address_prefixes,
                "destination_port_range": rule.destination_port_range,
                "destination_port_ranges": rule.destination_port_ranges
            })

        # Check the rules for open RDP and SSH
        result = analyze_nsg(nsg.name, rules)
        result["location"] = nsg.location

        nsgs.append(result)

    return nsgs
