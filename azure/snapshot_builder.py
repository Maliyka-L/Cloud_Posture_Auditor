from collector import (
    get_resource_groups,
    get_resources,
    get_storage_accounts
)


def build_snapshot(credential):

    snapshot = {
    "resource_groups": get_resource_groups(credential),
    "resources": get_resources(credential),
    "storage_accounts": get_storage_accounts(credential),
    "network_security_groups": [],
    "users": []
    }

    return snapshot