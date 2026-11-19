from auth import get_credential
from snapshot_builder import build_snapshot

credential = get_credential()

snapshot = build_snapshot(credential)

print(snapshot)