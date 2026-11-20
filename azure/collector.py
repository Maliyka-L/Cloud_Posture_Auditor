from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient

SUBSCRIPTION_ID = "8203953a-da5b-464e-989a-b65f39ab42d4"


def get_resource_groups(credential):

    client = ResourceManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    groups = []

    for group in client.resource_groups.list():

        groups.append({
            "name": group.name,
            "location": group.location
        })

    return groups


def get_storage_accounts(credential):

    client = StorageManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    accounts = []

    for account in client.storage_accounts.list():

        accounts.append({
            "name": account.name,
            "location": account.location
        })

    return accounts


def get_resources(credential):

    client = ResourceManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    resources = []

    for resource in client.resources.list():

        resources.append({
            "name": resource.name,
            "type": resource.type,
            "location": resource.location
        })

    return resources
