from azure.mgmt.storage import StorageManagementClient

SUBSCRIPTION_ID = "8203953a-da5b-464e-989a-b65f39ab42d4"


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