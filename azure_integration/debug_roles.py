from azure_integration.identity import InteractiveBrowserCredential
from azure_integration.mgmt.authorization import AuthorizationManagementClient

SUBSCRIPTION_ID = "8203953a-da5b-464e-989a-b65f39ab42d4"

credential = InteractiveBrowserCredential()

client = AuthorizationManagementClient(
    credential,
    SUBSCRIPTION_ID
)

print(dir(client.role_assignments))