---
pretty_name: Biosecurity Agent Production Worlds
license: apache-2.0
task_categories:
  - other
language:
  - en
tags:
  - osint
  - biosecurity
  - agent-trajectories
  - simulations
  - provenance
configs:
  - config_name: targets
    data_files:
      - split: train
        path: data/targets.parquet
  - config_name: entities
    data_files:
      - split: train
        path: data/entities.parquet
  - config_name: world_snapshots
    data_files:
      - split: train
        path: data/world_snapshots.parquet
  - config_name: source_events
    data_files:
      - split: train
        path: data/source_events.parquet
  - config_name: relationships
    data_files:
      - split: train
        path: data/relationships.parquet
  - config_name: agent_runs
    data_files:
      - split: train
        path: data/agent_runs.parquet
  - config_name: simulation_rollouts
    data_files:
      - split: train
        path: data/simulation_rollouts.parquet
  - config_name: protections
    data_files:
      - split: train
        path: data/protections.parquet
  - config_name: source_registry
    data_files:
      - split: train
        path: data/source_registry.parquet
---

# Biosecurity Agent Production Worlds

A dataset of target-conditioned biosecurity worlds, live OSINT context, real Codex-agent trajectories, and predictive simulations generated with Biosecurity Agent. It is a relational collection for studying how an agent builds and updates evidence-grounded worlds around specific targets; it is not a clinical dataset, an outbreak ground-truth benchmark, or a claim of predictive accuracy.

## Configurations

| Configuration | Contents | Rows |
| --- | --- | ---: |
| `targets` | Public-real and explicitly synthetic targets | 27 |
| `entities` | Normalized world entities | 84 |
| `world_snapshots` | Observed and simulated temporal states | 29 |
| `source_events` | Retrieved/discovered source records and normalized claims | 90 |
| `relationships` | Evidence-linked target and entity relationships | 66 |
| `agent_runs` | Observable structured Codex run results | 27 |
| `simulation_rollouts` | Seeded defensive forecast forks | 18 |
| `protections` | Evidence-backed defensive suggestions | 10 |
| `source_registry` | Source access, health, rights, and limitation metadata | 19 |

The dataset also contains 170 observable agent lifecycle events in `traces/agent_traces.jsonl`. Stable IDs—including `target_set_id`, `world_id`, `target_id`, `snapshot_id`, `source_event_id`, and `agent_run_id`—join the configurations. JSON Schemas are provided under `schemas/`; `MANIFEST.json` records frozen provenance and row counts.

## How it was generated

Nine multi-target configurations were run through a clean installation of the packaged Biosecurity Agent CLI. Each world used the authenticated Codex provider, bounded live public-source retrieval, isolated untrusted content, persisted SQLite state, target watchers, and labelled simulations. All worlds reached the `live` phase. The exported corpus contains 27 successful Codex trajectories—one target-modelling result and two structured conversational results per target set—with non-zero usage and retained lifecycle metadata. Demo and Mock Agent output are excluded.

Records were exported only from persisted product tables. The package used for generation was `@forsy/biosecurity-agent` 0.1.0 with SHA-256 `a4a8e554449b700ba4df1e4cb6a99593ea2b7e247c48f3160587ce1822679c80`; `MANIFEST.json` separately identifies the final hardened candidate. Prompt text, hidden reasoning, raw retrieved bodies, upload bodies, credentials, and notification secrets were not exported.

## Targets and labels

The nine target sets cover food products and supply chains, livestock and veterinary operations, wildlife, public-health facilities, ports and travel, wastewater and schools, national surveillance, and plant health across several geographies. Eighteen targets are labelled `public_real`. Nine household, family, team, traveller, or garden contexts are synthetic composites and are labelled `synthetic`; they do not describe real private people or addresses.

Claim states are intentionally distinct:

- `observed` records come from retrieved, isolated sources or explicitly synthetic user context. Retrieval does not establish exposure, causation, or diagnosis.
- `inferred` is reserved for product-derived interpretation. This frozen release contains no standalone inferred claims.
- `simulated` records are seeded defensive projections forked from named live snapshots and never merged into observed history.
- `material_bool` is the product's target-relevance decision. The corpus retains 12 material and 78 non-material records so retrieval is not misrepresented as relevance.

## Intended use

The data can support research and evaluation in target-aware retrieval, provenance, source-grounded world construction, temporal state reasoning, agent observability, defensive simulation, and evidence-linked protection. It should not be used for diagnosis, individual risk scoring, autonomous intervention, offensive biological work, or training systems to treat simulated outcomes as observations.

## Safety and privacy

External records passed through the product's raw → isolated parser → structured claims → evidence-store boundary. Source text could not alter agent instructions, notification destinations, tool registrations, or approval policy. The release contains no API keys, bearer tokens, SMTP/webhook credentials, private filesystem paths, email addresses, real personal records, hidden chain-of-thought, wet-lab procedures, or pathogen-engineering instructions. Protection proposals are defensive and approval-gated; none was executed in this corpus.

## Sources, copyright, and licence

Dataset-authored structured records and synthetic context metadata are released under Apache-2.0; see `LICENSE`. Linked source material is not relicensed. Rights in authority pages, literature, news, sensor data, and public posts remain with their publishers or authors. No full article, feed item, social post, PDF, abstract, or raw page body is redistributed. `source_events` contains public locators, hashes, metadata, security findings, and short product-generated normalized claims. The `source_registry` configuration records source-specific access methods, licence summaries, redistribution constraints, health states, and limitations. Users retrieving original material must follow the current source terms.

## Quality and limitations

All nine Parquet configurations load independently with Hugging Face `datasets`; the trace JSONL parses against its schema. Checksums, row counts, referential links, simulation bases, evidence links, agent success/provider status, privacy rules, claim-state separation, and source-body exclusion are validated by `schemas/validate_dataset.py`.

Public endpoints, rate limits, coverage, and licensing change over time. The corpus is English-dominant, discovery can be noisy, and some providers were access-limited during collection. The configured Codex model is recorded as `default` because an internal resolved model identifier was not persisted. Simulations use abstract reporting and exposure indices; they are reproducible scenario exercises, not calibrated epidemiological forecasts. No time-separated forecast checks are included because later verified ground truth was unavailable.
