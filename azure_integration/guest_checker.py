import requests

# Microsoft Graph settings
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users/{}"


# Raised when the account can't read the directory
class GraphPermissionError(Exception):
    pass


# Check if a user is an external guest
def is_guest(user):

    if str(user.get("userType", "")).lower() == "guest":
        return True

    return "#EXT#" in str(user.get("userPrincipalName", ""))


# Look up a user in Microsoft Graph
def lookup_user(token, principal_id):

    response = requests.get(
        GRAPH_USERS_URL.format(principal_id),
        headers={"Authorization": f"Bearer {token}"},
        params={"$select": "displayName,userPrincipalName,userType"},
        timeout=15
    )

    # No permission to read users
    if response.status_code in (401, 403):
        raise GraphPermissionError(response.text)

    # User not found
    if response.status_code == 404:
        return None

    response.raise_for_status()

    return response.json()


# Mark which role assignments belong to guest users
def mark_guest_users(credential, role_assignments):

    # Get a Microsoft Graph token
    try:
        token = credential.get_token(GRAPH_SCOPE).token
    except Exception:
        return "skipped"

    # Store users already looked up
    cache = {}

    try:
        for role in role_assignments:

            # Only check user accounts
            if role.get("principal_type") not in ("User", None):
                continue

            principal_id = role.get("principal_id")

            # Look up each user once
            if principal_id not in cache:
                cache[principal_id] = lookup_user(token, principal_id)

            user = cache[principal_id]

            if user:
                role["display_name"] = user.get("displayName")
                role["is_guest"] = is_guest(user)

    # No directory permission, so skip the check
    except GraphPermissionError:
        for role in role_assignments:
            role.pop("display_name", None)
            role.pop("is_guest", None)
        return "skipped"

    # Network error, so skip the check
    except requests.RequestException:
        return "skipped"

    return "completed"
