from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

# Azure Subscription ID
SUBSCRIPTION_ID = "8203953a-da5b-464e-989a-b65f39ab42d4"


# Collect Azure Resource Groups
def get_resource_groups(credential):

    # Create Resource Management client
    client = ResourceManagementClient(
        credential,
        SUBSCRIPTION_ID
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


# Collect Azure Storage Accounts
def get_storage_accounts(credential):

    # Create Storage Management client
    client = StorageManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    # Store storage accounts
    accounts = []

    # Loop through storage accounts
    for account in client.storage_accounts.list():

        accounts.append({
            "name": account.name,
            "location": account.location
        })

    return accounts


# Collect Azure Resources
def get_resources(credential):

    # Create Resource Management client
    client = ResourceManagementClient(
        credential,
        SUBSCRIPTION_ID
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
        SUBSCRIPTION_ID
    )

    # Store role assignments
    roles = []

    # Loop through subscription role assignments
    for assignment in client.role_assignments.list_for_subscription():

        roles.append({
            "role_definition_id": assignment.role_definition_id,
            "principal_id": assignment.principal_id
        })

    return roles