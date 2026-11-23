import os

from dotenv import load_dotenv
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

from azure_integration.role_mapper import get_role_name

load_dotenv()


def get_subscription_id():

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    if not subscription_id:
        raise ValueError(
            "AZURE_SUBSCRIPTION_ID is not set. Add it to your .env file."
        )

    return subscription_id


# Collect Azure Resource Groups
def get_resource_groups(credential):

    client = ResourceManagementClient(
        credential,
        get_subscription_id()
    )

    groups = []

    for group in client.resource_groups.list():

        groups.append({
            "name": group.name,
            "location": group.location
        })

    return groups


# Collect Azure Storage Accounts and their security settings
def get_storage_accounts(credential):

    client = StorageManagementClient(
        credential,
        get_subscription_id()
    )

    accounts = []

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

    client = ResourceManagementClient(
        credential,
        get_subscription_id()
    )

    resources = []

    for resource in client.resources.list():

        resources.append({
            "name": resource.name,
            "type": resource.type,
            "location": resource.location
        })

    return resources


# Collect Azure RBAC Role Assignments
def get_role_assignments(credential):

    client = AuthorizationManagementClient(
        credential,
        get_subscription_id()
    )

    roles = []

    for assignment in client.role_assignments.list_for_subscription():

        roles.append({
            "role_definition_id": assignment.role_definition_id,
            "role_name": get_role_name(assignment.role_definition_id),
            "principal_id": assignment.principal_id,
            "principal_type": getattr(assignment, "principal_type", None)
        })

    return roles
