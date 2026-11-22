# Map findings to CIS Azure controls

CIS_MAPPINGS = {

    "Privileged Owner Account": {
        "framework":
            "CIS Microsoft Azure Foundations Benchmark",

        "control":
            "Role Based Access Control"
    },

    "Multiple Owner Accounts": {
        "framework":
            "CIS Microsoft Azure Foundations Benchmark",

        "control":
            "Least Privilege"
    },

    "User Access Administrator Detected": {
        "framework":
            "CIS Microsoft Azure Foundations Benchmark",

        "control":
            "Access Management"
    }
}


# Return CIS mapping information
def get_cis_mapping(finding_title):

    return CIS_MAPPINGS.get(
        finding_title,
        {
            "framework": "Not Mapped",
            "control": "Not Mapped"
        }
    )