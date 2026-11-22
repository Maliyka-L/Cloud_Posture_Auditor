# Built-in Azure role IDs

ROLE_MAPPINGS = {

    # Owner
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635":
        "Owner",

    # Contributor
    "b24988ac-6180-42a0-ab88-20f7382dd24c":
        "Contributor",

    # Reader
    "acdd72a7-3385-48ef-bd42-f606fba81ae7":
        "Reader",

    # User Access Administrator
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9":
        "User Access Administrator"
}


# Convert Azure role IDs into readable names
def get_role_name(role_definition_id):

    # Extract GUID from Azure role path
    role_id = role_definition_id.split("/")[-1]

    # Return role name
    return ROLE_MAPPINGS.get(
        role_id,
        "Unknown Role"
    )