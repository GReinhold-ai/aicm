"""
Minimal, dependency-free illustration of the AICM commit-boundary check.
See the README Quickstart for the full sensor + server (AICMSensor) flow.

Commit-boundary authorization replay.

Takes a post-exploitation action chain (modeled on the July 2026 Hugging Face
disclosure) and runs each proposed commit through an authorization gate scoped
to the acting workload identity. The gate does not classify content or infer
intent. It asks one question per commit: is THIS identity authorized to perform
THIS action against THIS resource? In scope -> allow. Out of scope -> refuse.

The point of the replay: the initial code execution was a vulnerability. The
breach was the chain that followed -- escalate, harvest, move, exfiltrate. Every
one of those is a commit against a protected resource, and every one is outside
a dataset-processing worker's scope. A boundary bites here even when the model,
the filter, and the perimeter did not.
"""

import json
import hashlib
from datetime import datetime, timezone
from fnmatch import fnmatch

# The acting identity's authorized envelope. Everything else is out of scope.
SCOPE = {
    "identity": "ds-worker-14",
    "allowed": {
        "process_dataset": ["assigned/*"],
        "read_dataset": ["assigned/*"],
        "write_output": ["assigned/*"],
    },
}


def authorized(action: str, target: str) -> bool:
    patterns = SCOPE["allowed"].get(action)
    if not patterns:
        return False
    return any(fnmatch(target, p) for p in patterns)


def audit(prev_hash, act, verdict):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "identity": SCOPE["identity"],
        "checkpoint": "PRE_COMMIT",
        "seq": act["seq"],
        "action": act["action"],
        "target": act["target"],
        "decision": verdict,
        "prev_hash": prev_hash,
    }
    entry["record_hash"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True).encode()).hexdigest()
    return entry


def run(path):
    with open(path) as f:
        chain = json.load(f)

    print(f"identity : {chain['workload_identity']}")
    print(f"scope    : {chain['identity_scope']}\n")
    print(f"{'seq':>3}  {'action':<18} {'target':<26} decision")
    print("-" * 66)

    log, prev = [], "GENESIS"
    refused = 0
    for act in chain["actions"]:
        ok = authorized(act["action"], act["target"])
        verdict = "ALLOW" if ok else "REFUSE"
        if not ok:
            refused += 1
        print(f"{act['seq']:>3}  {act['action']:<18} {act['target']:<26} {verdict}"
              + ("" if ok else "  <- chain breaks here"))
        entry = audit(prev, act, verdict)
        log.append(entry)
        prev = entry["record_hash"]

    print("-" * 66)
    print(f"{refused} of {len(chain['actions'])} commits refused at the boundary.")
    print("The one allowed action was the worker doing its actual job.\n")
    print("Every attempt -- allowed or refused -- is written to a hash-chained record.")
    print(f"Final chain hash: {prev[:32]}...")

    with open("hf_replay_audit_log.json", "w") as f:
        json.dump(log, f, indent=2)


if __name__ == "__main__":
    run("hf_replay_actions.json")
