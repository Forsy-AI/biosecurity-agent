import { afterEach, describe, expect, it } from "vitest";
import { WatcherSchema } from "@biosecurity/contracts";
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
});
