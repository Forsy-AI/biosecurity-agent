#!/usr/bin/env python3
import hashlib, json, pathlib, re
from collections import Counter
import pyarrow.parquet as pq

root = pathlib.Path(__file__).resolve().parents[1]
manifest = json.loads((root / "MANIFEST.json").read_text())
names = [name for name in manifest["row_counts"] if name != "agent_traces"]
tables = {name: pq.read_table(root / f"data/{name}.parquet").to_pylist() for name in names}
traces = [json.loads(line) for line in (root / "traces/agent_traces.jsonl").read_text().splitlines()]
for name, expected in manifest["row_counts"].items():
    actual = len(traces) if name == "agent_traces" else len(tables[name])
    assert actual == expected, (name, actual, expected)

targets = {x["target_id"] for x in tables["targets"]}
entities = {x["entity_id"] for x in tables["entities"]}
snapshots = {x["snapshot_id"] for x in tables["world_snapshots"]}
events = {x["source_event_id"] for x in tables["source_events"]}
claims = {x["claim_id"] for x in tables["source_events"] if x["claim_id"]}
relationships = {x["relationship_id"] for x in tables["relationships"]}
protections = {x["protection_id"] for x in tables["protections"]}
agent_runs = {x["agent_run_id"] for x in tables["agent_runs"]}
simulation_claims = {cid for x in tables["simulation_rollouts"] for cid in x["generated_claim_ids"]}
for row in tables["world_snapshots"]:
    assert set(row["target_ids"]) <= targets
    assert set(row["entity_ids"]) <= entities
    assert set(row["observation_ids"]) <= claims | simulation_claims
    assert set(row["relationship_ids"]) <= relationships
    assert set(row["protection_ids"]) <= protections
for row in tables["relationships"]:
    assert row["source_entity_id"] in entities | targets
    assert row["target_entity_id"] in entities | targets
    assert set(row["evidence_ids"]) <= events
    assert row["snapshot_id"] in snapshots
for row in tables["protections"]:
    assert set(row["target_ids"]) <= targets and set(row["evidence_ids"]) <= events
for row in tables["simulation_rollouts"]:
    assert row["base_snapshot_id"] in snapshots and row["final_snapshot_id"] in snapshots
for row in tables["agent_runs"]:
    assert row["provider"] == "codex" and row["success"] and not row["fallback"]
    assert row["final_snapshot_id"] in snapshots and row["total_tokens"] > 0
assert all(row["agent_run_id"] in agent_runs and not row["hidden_reasoning_included"] for row in traces)
assert set(Counter(x["target_set_id"] for x in tables["agent_runs"]).values()) == {3}
assert set(Counter(x["target_set_id"] for x in tables["simulation_rollouts"]).values()) == {2}


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


config_text = "\n".join(path.read_text() for path in sorted((root / "configs").glob("*.json")))
exported_text = "\n".join(
    list(strings(tables)) + list(strings(traces)) + [config_text]
)
for pattern in (
    r"/(?:Users|home)/",
    r"/private/(?:tmp)/",
    r"[A-Za-z]:\\\\Users\\\\",
    r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bsk-[A-Za-z0-9_-]{20,}\b",
    r"\bBearer\s+[A-Za-z0-9._-]{16,}\b",
):
    assert not re.search(pattern, exported_text, re.IGNORECASE), pattern
assert not re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", exported_text, re.IGNORECASE)
assert not re.search(
    r"chain[- ]of[- ]thought|internal monologue|private scratchpad|system prompt|developer message",
    exported_text,
    re.IGNORECASE,
)
assert not re.search(
    r"weaponiz|increase virulence|enhance pathogenic|synthesi[sz]e.{0,30}(?:virus|pathogen)|"
    r"culture.{0,30}(?:virus|pathogen)|step[- ]by[- ]step.{0,60}(?:culture|pathogen|virus)",
    exported_text,
    re.IGNORECASE,
)

source_columns = set(tables["source_events"][0])
assert not source_columns & {"raw", "raw_body", "body", "content", "excerpt", "full_text"}
assert max(len(row["normalized_claim"]) for row in tables["source_events"]) <= 500
assert {row["claim_state"] for row in tables["source_events"]} == {"observed"}
assert claims.isdisjoint(simulation_claims)
for row in tables["world_snapshots"]:
    if row["snapshot_state"] == "simulated":
        assert row["base_snapshot_id"] in snapshots and row["simulated_claim_count"] > 0
    else:
        assert row["snapshot_state"] == "observed" and row["simulated_claim_count"] == 0
assert all(row["target_reality"] in {"public_real", "synthetic"} for row in tables["targets"])

for line in (root / "checksums.sha256").read_text().splitlines():
    digest, relative = line.split("  ", 1)
    assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest, relative
print(json.dumps({
    "status": "PASS",
    "row_counts": manifest["row_counts"],
    "referential_integrity": True,
    "checksums": True,
    "privacy_and_secret_scan": True,
    "claim_state_separation": True,
    "source_body_exclusion": True,
    "biological_enablement_scan": True,
}, indent=2))
