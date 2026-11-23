import requests

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users/{}"


class GraphPermissionError(Exception):
    pass


def is_guest(user):

    if str(user.get("userType", "")).lower() == "guest":
        return True

    return "#EXT#" in str(user.get("userPrincipalName", ""))


def lookup_user(token, principal_id):

    response = requests.get(
        GRAPH_USERS_URL.format(principal_id),
        headers={"Authorization": f"Bearer {token}"},
        params={"$select": "displayName,userPrincipalName,userType"},
        timeout=15
    )

    if response.status_code in (401, 403):
        raise GraphPermissionError(response.text)

    if response.status_code == 404:
        return None

    response.raise_for_status()

    return response.json()


def mark_guest_users(credential, role_assignments):

    try:
        token = credential.get_token(GRAPH_SCOPE).token
    except Exception:
        return "skipped"

    cache = {}

    try:
        for role in role_assignments:

            if role.get("principal_type") not in ("User", None):
                continue

            principal_id = role.get("principal_id")

            if principal_id not in cache:
                cache[principal_id] = lookup_user(token, principal_id)

            user = cache[principal_id]

            if user:
                role["display_name"] = user.get("displayName")
                role["is_guest"] = is_guest(user)

    except GraphPermissionError:
        for role in role_assignments:
            role.pop("display_name", None)
            role.pop("is_guest", None)
        return "skipped"

    except requests.RequestException:
        return "skipped"

    return "completed"
