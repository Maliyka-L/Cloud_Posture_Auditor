from auth import get_credential
from snapshot_builder import build_snapshot
from posture import calculate_posture

# Authenticate to Azure
credential = get_credential()

# Build live Azure snapshot
snapshot = build_snapshot(
    credential
)

# Calculate posture score
results = calculate_posture(
    snapshot
)

print("\nAzure Security Posture\n")

print(
    f"Score: {results['score']}"
)

print("\nFindings:\n")

for finding in results["findings"]:

    print(
        f"- {finding}"
    )