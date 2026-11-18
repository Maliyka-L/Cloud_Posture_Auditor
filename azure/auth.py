from azure.identity import InteractiveBrowserCredential


def get_credential():
    return InteractiveBrowserCredential()