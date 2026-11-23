import json

from azure_integration.auth import get_credential
from azure_integration.snapshot_builder import build_snapshot

# Authenticate to Azure
credential = get_credential()

# Build live Azure snapshot
snapshot = build_snapshot(credential)

# Display the snapshot
print(json.dumps(snapshot, indent=4))
