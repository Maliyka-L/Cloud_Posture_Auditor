from azure_integration.collector import (
    get_resource_groups,
    get_resources,
    get_storage_accounts,
    get_role_assignments,
    get_network_security_groups
)
from azure_integration.guest_checker import mark_guest_users


# Build complete Azure snapshot
def build_snapshot(credential):

    role_assignments = get_role_assignments(credential)

    guest_check = mark_guest_users(credential, role_assignments)

    snapshot = {
        "resource_groups": get_resource_groups(credential),
        "resources": get_resources(credential),
        "storage_accounts": get_storage_accounts(credential),
        "role_assignments": role_assignments,
        "guest_check": guest_check,
        "network_security_groups": get_network_security_groups(credential),
        "users": []
    }

    return snapshot
