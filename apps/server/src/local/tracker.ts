import { nanoid } from "nanoid";
import { ProcessingEventSchema, WorldSnapshotSchema, type Watcher } from "@biosecurity/contracts";
import type { BiosecurityDatabase } from "./state.js";

export type WatchResult = {
  cursor?: string;
  material: boolean;
  summary?: string;
  artifactIds?: string[];
  entityIds?: string[];
  claimIds?: string[];
  materialClaimIds?: string[];
  evidenceIds?: string[];
};
export type WatchRunner = (watcher: Watcher) => Promise<WatchResult>;
export type MaterialChangeHandler = (input: {
  watcher: Watcher;
  snapshot: ReturnType<BiosecurityDatabase["listSnapshots"]>[number];
  summary: string;
  evidenceIds: string[];
}) => Promise<void>;

export class LiveTracker {
  readonly database: BiosecurityDatabase;
  readonly runner: WatchRunner;
  readonly timers = new Map<string, NodeJS.Timeout>();
  readonly attempts = new Map<string, number>();
  readonly running = new Set<Promise<void>>();
  readonly onMaterialChange?: MaterialChangeHandler;
  stopped = false;

  constructor(
    database: BiosecurityDatabase,
    runner?: WatchRunner,
    onMaterialChange?: MaterialChangeHandler,
  ) {
    this.database = database;
    this.runner =
      runner ??
      (async (watcher) => ({ cursor: watcher.cursor ?? `cursor:${Date.now()}`, material: false }));
    this.onMaterialChange = onMaterialChange;
  }

  start(): void {
    this.stopped = false;
    for (const watcher of this.database.listWatchers()) this.schedule(watcher, 50);
  }

  schedule(watcher: Watcher, delayMs = watcher.cadence * 1000): void {
    if (this.stopped) return;
    const previous = this.timers.get(watcher.id);
    if (previous) clearTimeout(previous);
    const timer = setTimeout(
      () => {
        if (this.stopped) return;
        const task = this.runWatcher(watcher.id);
        this.running.add(task);
        void task.finally(() => this.running.delete(task));
      },
      Math.max(10, delayMs),
    );
    timer.unref();
    this.timers.set(watcher.id, timer);
  }

  async runWatcher(watcherId: string): Promise<void> {
    const watcher = this.database.listWatchers().find((item) => item.id === watcherId);
    if (!watcher || watcher.health === "paused") return;
    try {
      const result = await this.runner(watcher);
      const now = new Date().toISOString();
      const latest = this.database.listWatchers().find((item) => item.id === watcher.id) ?? watcher;
      const firstSuccessfulRun = latest.lastSuccessfulRun === null;
      const updated: Watcher = {
        ...latest,
        cursor: result.cursor ?? latest.cursor,
        lastSuccessfulRun: now,
        lastMaterialUpdate: result.material ? now : latest.lastMaterialUpdate,
        health: "healthy",
      };
      this.database.saveWatcher(updated);
      this.attempts.delete(watcher.id);
      if (firstSuccessfulRun) {
        this.database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_watch_${nanoid(10)}`,
            runId: watcher.runId,
            lane: "LIVE WATCH",
            type: "watcher.active",
            status: "completed",
            label: `Watcher active · ${watcher.language.toUpperCase()} · ${watcher.geography}`,
            createdAt: now,
            metadata: { watcherId: watcher.id, providers: watcher.sourceProviders.length },
          }),
        );
      }
      if (result.material)
        await this.persistMaterialUpdate(
          updated,
          result.summary ?? "Material target update found",
          result,
        );
      this.schedule(updated);
    } catch (error) {
      const attempt = (this.attempts.get(watcher.id) ?? 0) + 1;
      this.attempts.set(watcher.id, attempt);
      const latest = this.database.listWatchers().find((item) => item.id === watcher.id) ?? watcher;
      const updated: Watcher = { ...latest, health: "degraded" };
      this.database.saveWatcher(updated);
      this.database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_watch_${nanoid(10)}`,
          runId: watcher.runId,
          lane: "LIVE WATCH",
          type: "watcher.failed",
          status: "failed",
          label: `Watcher retry scheduled after bounded failure: ${(error as Error).message}`,
          createdAt: new Date().toISOString(),
          metadata: { watcherId, attempt },
        }),
      );
      this.schedule(updated, Math.min(watcher.cadence * 1000, 1_000 * 2 ** Math.min(attempt, 6)));
    }
  }

  async persistMaterialUpdate(
    watcher: Watcher,
    summary: string,
    references: Pick<
      WatchResult,
      "artifactIds" | "entityIds" | "claimIds" | "materialClaimIds" | "evidenceIds"
    > = {},
  ): Promise<void> {
    const snapshots = this.database.listSnapshots(watcher.runId);
    const previous = snapshots.filter((snapshot) => !snapshot.simulation).at(-1);
    if (!previous) return;
    const event = ProcessingEventSchema.parse({
      id: `event_watch_${nanoid(10)}`,
      runId: watcher.runId,
      lane: "LIVE WATCH",
      type: "material.update",
      status: "completed",
      label: summary,
      createdAt: new Date().toISOString(),
      metadata: { watcherId: watcher.id },
    });
    this.database.saveEvent(event);
    const snapshot = WorldSnapshotSchema.parse({
      ...previous,
      id: `snapshot_${nanoid(10)}`,
      asOf: new Date().toISOString(),
      entityIds: [...new Set([...previous.entityIds, ...(references.entityIds ?? [])])],
      claimIds: [...new Set([...previous.claimIds, ...(references.claimIds ?? [])])],
      materialChanges: [
        ...previous.materialChanges,
        {
          id: `change_${nanoid(8)}`,
          summary,
          targetIds: watcher.targetIds,
          claimIds: references.materialClaimIds ?? references.claimIds ?? [],
          significance: "medium",
        },
      ],
      provenance: {
        artifactIds: [
          ...new Set([...previous.provenance.artifactIds, ...(references.artifactIds ?? [])]),
        ],
        observedClaims: new Set([...previous.claimIds, ...(references.claimIds ?? [])]).size,
      },
    });
    this.database.saveSnapshot(watcher.runId, snapshot);
    await this.onMaterialChange?.({
      watcher,
      snapshot,
      summary,
      evidenceIds: references.evidenceIds ?? [],
    });
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    await Promise.allSettled(this.running);
  }
}
