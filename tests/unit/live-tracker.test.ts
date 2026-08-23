import { afterEach, describe, expect, it } from "vitest";
import { WatcherSchema, WorldSnapshotSchema } from "@biosecurity/contracts";
import { LiveTracker, type WatchResult } from "../../apps/server/src/local/tracker.js";
import { BiosecurityDatabase } from "../../apps/server/src/local/state.js";

const databases: BiosecurityDatabase[] = [];
afterEach(() => databases.splice(0).forEach((database) => database.close()));

describe("live tracker persistence", () => {
  it("does not overwrite source configuration changed during an in-flight poll", async () => {
    const database = await BiosecurityDatabase.open(":memory:", true);
    databases.push(database);
    const run = database.createRun("mock", "deterministic-mock-v1");
    let finish!: (result: WatchResult) => void;
    const runner = new Promise<WatchResult>((resolve) => (finish = resolve));
    const watcher = WatcherSchema.parse({
      id: "watcher_concurrency",
      runId: run.id,
      targetIds: ["target_concurrency"],
      query: "public plant health",
      sourceProviders: ["who-don"],
      cadence: 900,
      language: "en",
      geography: "Kent",
      cursor: null,
      lastSuccessfulRun: null,
      lastMaterialUpdate: null,
      health: "starting",
    });
    database.saveWatcher(watcher);
    const tracker = new LiveTracker(database, () => runner);

    const polling = tracker.runWatcher(watcher.id);
    database.saveWatcher({
      ...watcher,
      sourceProviders: [...watcher.sourceProviders, "custom:source_feed"],
    });
    finish({ cursor: "poll:complete", material: false });
    await polling;

    expect(database.listWatchers()[0]).toMatchObject({
      sourceProviders: ["who-don", "custom:source_feed"],
      cursor: "poll:complete",
      health: "healthy",
    });
    await tracker.stop();
  });

  it("forks live updates from the latest observed snapshot rather than a simulation", async () => {
    const database = await BiosecurityDatabase.open(":memory:", true);
    databases.push(database);
    const run = database.createRun("mock", "deterministic-mock-v1");
    const watcher = WatcherSchema.parse({
      id: "watcher_snapshot_boundary",
      runId: run.id,
      targetIds: ["target_snapshot_boundary"],
      query: "public plant health",
      sourceProviders: ["who-don"],
      cadence: 900,
      language: "en",
      geography: "Kent",
      cursor: null,
      lastSuccessfulRun: null,
      lastMaterialUpdate: null,
      health: "healthy",
    });
    database.saveWatcher(watcher);
    const base = WorldSnapshotSchema.parse({
      id: "snapshot_observed_base",
      worldId: `world_${run.id}`,
      asOf: "2026-08-23T00:00:00.000Z",
      targetIds: watcher.targetIds,
      entityIds: ["entity_observed"],
      claimIds: ["claim_observed_base"],
      materialChanges: [],
      protectionIds: [],
      coverage: {
        searchedClasses: ["authority"],
        unavailableProviders: [],
        languages: ["en"],
        limitations: [],
      },
      provenance: { artifactIds: ["artifact_observed_base"], observedClaims: 1 },
    });
    const simulated = WorldSnapshotSchema.parse({
      ...base,
      id: "snapshot_simulated_branch",
      asOf: "2026-08-23T01:00:00.000Z",
      claimIds: [...base.claimIds, "claim_simulated"],
      materialChanges: [
        {
          id: "change_simulated",
          summary: "Simulated change",
          targetIds: watcher.targetIds,
          claimIds: ["claim_simulated"],
          significance: "medium",
        },
      ],
      simulation: {
        baseSnapshotId: base.id,
        seed: 7331,
        horizon: "14d",
        generatedAt: "2026-08-23T01:00:00.000Z",
      },
    });
    database.saveSnapshot(run.id, base);
    database.saveSnapshot(run.id, simulated);

    const tracker = new LiveTracker(database);
    await tracker.persistMaterialUpdate(watcher, "Observed material update", {
      artifactIds: ["artifact_observed_new"],
      entityIds: ["entity_observed_new"],
      claimIds: ["claim_observed_new"],
      materialClaimIds: ["claim_observed_new"],
    });

    const latest = database.listSnapshots(run.id).at(-1)!;
    expect(latest.simulation).toBeUndefined();
    expect(latest.claimIds).toEqual(["claim_observed_base", "claim_observed_new"]);
    expect(latest.materialChanges).toEqual([
      expect.objectContaining({ summary: "Observed material update" }),
    ]);
    expect(latest.provenance.observedClaims).toBe(2);
    await tracker.stop();
  });
});
