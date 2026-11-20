from auth import get_credential
from snapshot_builder import build_snapshot

import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from auditor import run_audit

credential = get_credential()

snapshot = build_snapshot(credential)

findings = run_audit(snapshot)

print("\nFindings:\n")

if not findings:

    print(
        "No security findings detected."
    )

for finding in findings:

    print(
        f"[{finding['severity']}] "
        f"{finding['title']}"
    )