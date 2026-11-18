from azure.mgmt.resource.resources import ResourceManagementClient

SUBSCRIPTION_ID = "8203953a-da5b-464e-989a-b65f39ab42d4"


def get_resource_groups(credential):

    client = ResourceManagementClient(
        credential,
        SUBSCRIPTION_ID
    )

    groups = []

    for group in client.resource_groups.list():

        groups.append(
            {
                "name": group.name,
                "location": group.location
            }
        )

    return groups