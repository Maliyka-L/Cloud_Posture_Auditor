import json

from azure_integration.auth import get_credential
from azure_integration.snapshot_builder import build_snapshot

credential = get_credential()

snapshot = build_snapshot(credential)

print(json.dumps(snapshot, indent=4))
