from azure.identity import InteractiveBrowserCredential

# Create Azure credential
def get_credential():

    return InteractiveBrowserCredential()