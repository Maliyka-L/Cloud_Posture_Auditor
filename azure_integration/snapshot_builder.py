from azure_integration.collector import (
    get_resource_groups,
    get_resources,
    get_storage_accounts,
    get_role_assignments,
    get_network_security_groups
)


# Build complete Azure snapshot
def build_snapshot(credential):

    snapshot = {
        "resource_groups": get_resource_groups(credential),
        "resources": get_resources(credential),
        "storage_accounts": get_storage_accounts(credential),
        "role_assignments": get_role_assignments(credential),
        "network_security_groups": get_network_security_groups(credential),
        "users": []
    }

    return snapshot
