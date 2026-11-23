import requests

from azure_integration import guest_checker
from azure_integration.guest_checker import is_guest, mark_guest_users
from azure_integration.rbac_auditor import analyze_roles


# Fake Azure token
class FakeToken:
    token = "fake-token"


# Fake Azure credential
class FakeCredential:
    def get_token(self, scope):
        return FakeToken()


# Fake Microsoft Graph response
class FakeResponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self.data = data or {}
        self.text = ""

    def json(self):
        return self.data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.status_code)


# Get finding titles
def titles(findings):
    return [finding["title"] for finding in findings]


# Guest detection by user type and #EXT# name
def test_is_guest():
    assert is_guest({"userType": "Guest"})
    assert is_guest({"userPrincipalName": "jo_gmail.com#EXT#@uni.onmicrosoft.com"})
    assert not is_guest({"userType": "Member", "userPrincipalName": "me@uni.ac.uk"})


# Guests and members are marked correctly
def test_guests_marked(monkeypatch):
    users = {
        "guest-id": {"displayName": "External Jo", "userType": "Guest"},
        "member-id": {"displayName": "Me", "userType": "Member"}
    }

    def fake_get(url, **kwargs):
        return FakeResponse(200, users[url.rsplit("/", 1)[-1]])

    monkeypatch.setattr(guest_checker.requests, "get", fake_get)

    roles = [
        {"principal_id": "guest-id", "principal_type": "User", "role_name": "Owner"},
        {"principal_id": "member-id", "principal_type": "User", "role_name": "Owner"},
        {"principal_id": "app-id", "principal_type": "ServicePrincipal", "role_name": "Reader"}
    ]

    assert mark_guest_users(FakeCredential(), roles) == "completed"
    assert roles[0]["is_guest"] is True
    assert roles[1]["is_guest"] is False
    assert "is_guest" not in roles[2]


# No permission skips the check
def test_skipped_without_permission(monkeypatch):
    monkeypatch.setattr(
        guest_checker.requests, "get",
        lambda url, **kwargs: FakeResponse(403)
    )

    roles = [{"principal_id": "x", "principal_type": "User", "role_name": "Owner"}]

    assert mark_guest_users(FakeCredential(), roles) == "skipped"
    assert "is_guest" not in roles[0]


# Guest Owner is HIGH
def test_guest_owner_finding():
    roles = [{"principal_id": "x", "display_name": "External Jo",
              "role_name": "Owner", "is_guest": True}]
    findings = analyze_roles(roles)

    assert titles(findings) == ["Guest User With Owner Access"]
    assert findings[0]["resource"] == "External Jo"


# Guest with other roles is MEDIUM
def test_guest_reader_finding():
    roles = [{"principal_id": "x", "role_name": "Reader", "is_guest": True}]

    assert titles(analyze_roles(roles)) == ["Guest User With Azure Access"]


# Member Owner is still a Privileged Owner
def test_member_owner_unchanged():
    roles = [{"principal_id": "x", "role_name": "Owner", "is_guest": False}]

    assert titles(analyze_roles(roles)) == ["Privileged Owner Account"]
