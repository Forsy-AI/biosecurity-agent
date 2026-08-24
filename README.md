# Biosecurity Agent

AI agent that builds a live biosecurity world around any target.

![Biosecurity Agent visual world](assets/bioworld.png)

## Quick Start

After npm publication:

```bash
npx @forsy/biosecurity-agent
```

From this release candidate:

```bash
npm install ./forsy-biosecurity-agent-0.1.2.tgz
npx biosecurity-agent
```

Configure your AI agent. Tell it what to protect. It starts investigating and tracking automatically.

Start with one target or a connected set, then refine them conversationally as the world changes. The terminal exposes each real processing lane from discovery and retrieval through claim extraction and synthesis while keeping the underlying evidence inspectable. Exit whenever you like; the local runtime restores the same targets, watchers, and world on your next launch.

### 1. Define targets

Describe people, animals, plants, products, places, organisations, or multiple connected targets in ordinary language. Files, private context, public URLs, and custom sources can add the details that make evidence relevant to you.

### 2. Live biosecurity

Your agent tracks official and scientific sources, news and the open web, public OSINT, sensors and surveillance, and connected data. It builds a target-centred biosecurity world, links evidence across places and time, and keeps that world updated in the background.

### 3. Predict + protect

From the current live state, the agent can simulate forward and recommend defensive actions backed by inspectable evidence. Observed, inferred, and simulated claims always remain distinct.

## Terminal

This excerpt comes from the persisted run shown above:

```text
TARGET MODELLING          ✓ 3 targets
OFFICIAL + SCIENTIFIC     ✓ 5 sources
NEWS + OPEN WEB           ✓ 4 sources
SOCIAL + COMMUNITY        ✓ 3 sources
SENSORS + SURVEILLANCE    ✓ 4 sources
CUSTOM SOURCES            ✓ 2 sources
WORLD SYNTHESIS           ✓ 18 entities · 18 relationships
LIVE WATCH                ● 3 watchers

SIMULATION · +14 DAYS
London household · Milo · Heathrow → Singapore
3 future paths · 1 protection · 3 evidence links
```

[Open the full terminal replay](assets/terminal-replay.log).

The terminal remains the controller for targets, sources, evidence, simulations, protection, and optional alerts. Its world, processing events, watchers, and target relationships persist locally and restore on restart.

## Visual viewer

Biosecurity Agent is terminal-first; `view` opens an optional read-only world visualizer for maps, relationships, evidence, and simulations.

## Agent compatibility

All agents and model providers are supported through the OpenAI-compatible adapter, with native Codex and Claude adapters.

## Privacy + safety

Biosecurity Agent runs locally. Targets, files, and secrets are not uploaded to us by default. External content is treated as untrusted, actions require explicit permissions, and the project is designed for defensive biosecurity, not pathogen engineering or clinical diagnosis.

## Dataset

https://huggingface.co/datasets/Forsy-AI/BiosecurityAgent01

## License

Apache-2.0. See [LICENSE](LICENSE).
