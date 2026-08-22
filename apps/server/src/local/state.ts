import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import Database from "better-sqlite3";
import { nanoid } from "nanoid";
import {
  ClaimSchema,
  EntitySchema,
  EvidenceRecordSchema,
  ProcessingEventSchema,
  ProtectionSchema,
  SourceArtifactSchema,
  TargetSchema,
  WatcherSchema,
  WorldSnapshotSchema,
  countsFromEvents,
  type Claim,
  type CustomSource,
  type Entity,
  type EvidenceRecord,
  type ProcessingEvent,
  type Protection,
  type SourceArtifact,
  type Target,
  type Watcher,
  type WorldSnapshot,
  type WorldView,
  AgentNotificationSchema,
  NotificationDeliverySchema,
  NotificationDestinationSchema,
  type AgentNotification,
  type NotificationDelivery,
  type NotificationDestination,
} from "@biosecurity/contracts";

type JsonRecord = Record<string, unknown>;

const parseJson = <T>(value: string): T => JSON.parse(value) as T;
const json = (value: unknown): string => JSON.stringify(value);

export interface SecretStore {
  readonly kind: "encrypted-file" | "environment" | "memory";
  set(name: string, value: string): Promise<void>;
  get(name: string): Promise<string | undefined>;
  delete(name: string): Promise<void>;
}

export class MemorySecretStore implements SecretStore {
  readonly kind = "memory" as const;
  readonly #values = new Map<string, string>();
  async set(name: string, value: string): Promise<void> {
    this.#values.set(name, value);
  }
  async get(name: string): Promise<string | undefined> {
    return this.#values.get(name);
  }
  async delete(name: string): Promise<void> {
    this.#values.delete(name);
  }
}

export class EnvironmentSecretStore implements SecretStore {
  readonly kind = "environment" as const;
  async set(): Promise<void> {
    throw new Error("Environment secret storage is read-only");
  }
  async get(name: string): Promise<string | undefined> {
    return process.env[name];
  }
  async delete(): Promise<void> {
    throw new Error("Environment secret storage is read-only");
  }
}

export class MemoryWithEnvironmentSecretStore implements SecretStore {
  readonly kind = "memory" as const;
  readonly #values = new Map<string, string>();

  async set(name: string, value: string): Promise<void> {
    this.#values.set(name, value);
  }

  async get(name: string): Promise<string | undefined> {
    return this.#values.get(name) ?? process.env[name];
  }

  async delete(name: string): Promise<void> {
    this.#values.delete(name);
  }
}

export class EncryptedFileSecretStore implements SecretStore {
  readonly kind = "encrypted-file" as const;
  readonly #file: string;
  readonly #key: Buffer;

  constructor(file: string, masterKey: string) {
    if (masterKey.length < 16)
      throw new Error("BIOSECURITY_MASTER_KEY must contain at least 16 characters");
    this.#file = file;
    this.#key = scryptSync(masterKey, "biosecurity-agent-secret-store-v1", 32);
  }

  async set(name: string, value: string): Promise<void> {
    const values = await this.#read();
    values[name] = value;
    await this.#write(values);
  }

  async get(name: string): Promise<string | undefined> {
    return (await this.#read())[name];
  }

  async delete(name: string): Promise<void> {
    const values = await this.#read();
    delete values[name];
    await this.#write(values);
  }

  async #read(): Promise<Record<string, string>> {
    try {
      const payload = parseJson<{ iv: string; tag: string; data: string }>(
        await readFile(this.#file, "utf8"),
      );
      const decipher = createDecipheriv(
        "aes-256-gcm",
        this.#key,
        Buffer.from(payload.iv, "base64"),
      );
      decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
      const clear = Buffer.concat([
        decipher.update(Buffer.from(payload.data, "base64")),
        decipher.final(),
      ]);
      return parseJson<Record<string, string>>(clear.toString("utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw error;
    }
  }

  async #write(values: Record<string, string>): Promise<void> {
    await mkdir(dirname(this.#file), { recursive: true, mode: 0o700 });
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.#key, iv);
    const encrypted = Buffer.concat([cipher.update(json(values), "utf8"), cipher.final()]);
    await writeFile(
      this.#file,
      json({
        iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
        data: encrypted.toString("base64"),
      }),
      { encoding: "utf8", mode: 0o600 },
    );
  }
}

export function createSecretStore(dataDir: string): SecretStore {
  if (process.env.BIOSECURITY_MASTER_KEY) {
    return new EncryptedFileSecretStore(
      join(dataDir, "secrets.enc"),
      process.env.BIOSECURITY_MASTER_KEY,
    );
  }
  return new MemoryWithEnvironmentSecretStore();
}

export type RunRecord = {
  id: string;
  phase: "building" | "live" | "failed";
  demo: boolean;
  agentProvider: string;
  agentModel: string;
  createdAt: string;
  updatedAt: string;
  error: string | null;
};

export class BiosecurityDatabase {
  readonly db: Database.Database;
  readonly dataDir: string;
  readonly subscribers = new Map<string, Set<(event: ProcessingEvent) => void>>();

  constructor(dataDir: string, memory = false) {
    this.dataDir = dataDir;
    const filename = memory ? ":memory:" : join(dataDir, "biosecurity.db");
    this.db = new Database(filename);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.migrate();
  }

  static async open(dataDir: string, memory = false): Promise<BiosecurityDatabase> {
    if (!memory) await mkdir(dataDir, { recursive: true, mode: 0o700 });
    return new BiosecurityDatabase(dataDir, memory);
  }

  migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY, phase TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0,
        agent_provider TEXT NOT NULL, agent_model TEXT NOT NULL,
        instruction_version TEXT NOT NULL DEFAULT 'v1', tool_calls_json TEXT NOT NULL DEFAULT '[]',
        tool_outputs_json TEXT NOT NULL DEFAULT '[]', structured_outputs_json TEXT NOT NULL DEFAULT '[]',
        usage_json TEXT NOT NULL DEFAULT '{}', latency_ms INTEGER, error TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        name TEXT NOT NULL, description TEXT NOT NULL, inferred_kind TEXT,
        attributes_json TEXT NOT NULL, locations_json TEXT NOT NULL,
        relationships_json TEXT NOT NULL, context_artifacts_json TEXT NOT NULL,
        custom_source_ids_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS artifacts (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        provider_id TEXT NOT NULL, source_class TEXT NOT NULL, url TEXT, title TEXT, author TEXT,
        language TEXT, published_at TEXT, observed_at TEXT, retrieved_at TEXT NOT NULL,
        content_hash TEXT NOT NULL, raw_storage_ref TEXT NOT NULL, licence TEXT, redistribution TEXT,
        trust_metadata_json TEXT NOT NULL, security_state TEXT NOT NULL, isolated_text TEXT NOT NULL DEFAULT ''
      );
      CREATE TABLE IF NOT EXISTS entities (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        kind TEXT NOT NULL, label TEXT NOT NULL, aliases_json TEXT NOT NULL,
        attributes_json TEXT NOT NULL, locations_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS aliases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        alias TEXT NOT NULL, UNIQUE(entity_id, alias)
      );
      CREATE TABLE IF NOT EXISTS claims (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
        subject_json TEXT NOT NULL, predicate TEXT NOT NULL, object_json TEXT NOT NULL,
        time_json TEXT, geography_json TEXT, evidence_span_json TEXT,
        confidence REAL NOT NULL, state TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS relationships (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        from_entity_id TEXT NOT NULL, to_entity_id TEXT NOT NULL, type TEXT NOT NULL,
        claim_ids_json TEXT NOT NULL, state TEXT NOT NULL, confidence REAL NOT NULL
      );
      CREATE TABLE IF NOT EXISTS snapshots (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        world_id TEXT NOT NULL, as_of TEXT NOT NULL, data_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS watchers (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        target_ids_json TEXT NOT NULL, query TEXT NOT NULL, source_providers_json TEXT NOT NULL,
        cadence INTEGER NOT NULL, language TEXT NOT NULL, geography TEXT NOT NULL, cursor TEXT,
        last_successful_run TEXT, last_material_update TEXT, health TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS processing_events (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        lane TEXT NOT NULL, type TEXT NOT NULL, status TEXT NOT NULL, label TEXT NOT NULL,
        entity_id TEXT, artifact_id TEXT, count_delta INTEGER,
        created_at TEXT NOT NULL, metadata_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_events_run_created ON processing_events(run_id, created_at);
      CREATE TABLE IF NOT EXISTS protections (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        data_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tool_proposals (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        protection_id TEXT NOT NULL, tool TEXT NOT NULL, arguments_json TEXT NOT NULL,
        status TEXT NOT NULL, approval_required INTEGER NOT NULL, executed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        data_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS custom_sources (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        kind TEXT NOT NULL, label TEXT NOT NULL, value TEXT NOT NULL, target_ids_json TEXT NOT NULL,
        mapping_json TEXT, enabled INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS uploaded_context (
        id TEXT PRIMARY KEY, run_id TEXT, filename TEXT NOT NULL, media_type TEXT NOT NULL,
        size INTEGER NOT NULL, storage_ref TEXT NOT NULL, security_state TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS notification_destinations (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        type TEXT NOT NULL, name TEXT NOT NULL, destination TEXT NOT NULL,
        target_ids_json TEXT NOT NULL, enabled INTEGER NOT NULL,
        allow_private_network INTEGER NOT NULL, include_sensitive INTEGER NOT NULL,
        simulation_notifications INTEGER NOT NULL, settings_json TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        fingerprint TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(run_id, fingerprint)
      );
      CREATE TABLE IF NOT EXISTS notification_deliveries (
        id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        notification_id TEXT NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
        destination_id TEXT NOT NULL REFERENCES notification_destinations(id) ON DELETE CASCADE,
        status TEXT NOT NULL, attempted_at TEXT NOT NULL, error_code TEXT, error_message TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_delivery_destination_time ON notification_deliveries(destination_id, attempted_at);
    `);
    try {
      this.db.exec(
        "CREATE VIRTUAL TABLE IF NOT EXISTS artifact_search USING fts5(artifact_id UNINDEXED, run_id UNINDEXED, title, content)",
      );
    } catch {
      // FTS5 may be absent in unusual SQLite builds; core storage remains available.
    }
  }

  createRun(agentProvider: string, agentModel: string, demo = false): RunRecord {
    const now = new Date().toISOString();
    const run: RunRecord = {
      id: `run_${nanoid(12)}`,
      phase: "building",
      demo,
      agentProvider,
      agentModel,
      createdAt: now,
      updatedAt: now,
      error: null,
    };
    this.db
      .prepare(
        "INSERT INTO runs (id, phase, demo, agent_provider, agent_model, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(run.id, run.phase, demo ? 1 : 0, agentProvider, agentModel, now, now);
    return run;
  }

  updateRunPhase(runId: string, phase: RunRecord["phase"], error: string | null = null): void {
    this.db
      .prepare("UPDATE runs SET phase = ?, error = ?, updated_at = ? WHERE id = ?")
      .run(phase, error, new Date().toISOString(), runId);
  }

  getRun(runId: string): RunRecord | undefined {
    const row = this.db.prepare("SELECT * FROM runs WHERE id = ?").get(runId) as any;
    return row
      ? {
          id: row.id,
          phase: row.phase,
          demo: Boolean(row.demo),
          agentProvider: row.agent_provider,
          agentModel: row.agent_model,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          error: row.error,
        }
      : undefined;
  }

  listRuns(): RunRecord[] {
    return (this.db.prepare("SELECT * FROM runs ORDER BY created_at DESC").all() as any[]).map(
      (row) => ({
        id: row.id,
        phase: row.phase,
        demo: Boolean(row.demo),
        agentProvider: row.agent_provider,
        agentModel: row.agent_model,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        error: row.error,
      }),
    );
  }

  saveTarget(runId: string, target: Target): void {
    const parsed = TargetSchema.parse(target);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO targets
        (id, run_id, name, description, inferred_kind, attributes_json, locations_json, relationships_json,
         context_artifacts_json, custom_source_ids_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        parsed.id,
        runId,
        parsed.name,
        parsed.description,
        parsed.inferredKind ?? null,
        json(parsed.attributes),
        json(parsed.locations),
        json(parsed.relationships),
        json(parsed.contextArtifacts),
        json(parsed.customSourceIds),
        parsed.createdAt,
        parsed.updatedAt,
      );
  }

  deleteTarget(runId: string, targetId: string): void {
    for (const watcher of this.listWatchers(runId)) {
      if (!watcher.targetIds.includes(targetId)) continue;
      const targetIds = watcher.targetIds.filter((id) => id !== targetId);
      if (targetIds.length === 0)
        this.db.prepare("DELETE FROM watchers WHERE id = ? AND run_id = ?").run(watcher.id, runId);
      else this.saveWatcher({ ...watcher, targetIds });
    }
    this.db.prepare("DELETE FROM targets WHERE run_id = ? AND id = ?").run(runId, targetId);
  }

  listTargets(runId: string): Target[] {
    return (
      this.db
        .prepare("SELECT * FROM targets WHERE run_id = ? ORDER BY created_at")
        .all(runId) as any[]
    ).map((row) =>
      TargetSchema.parse({
        id: row.id,
        name: row.name,
        description: row.description,
        ...(row.inferred_kind ? { inferredKind: row.inferred_kind } : {}),
        attributes: parseJson(row.attributes_json),
        locations: parseJson(row.locations_json),
        relationships: parseJson(row.relationships_json),
        contextArtifacts: parseJson(row.context_artifacts_json),
        customSourceIds: parseJson(row.custom_source_ids_json),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }),
    );
  }

  saveArtifact(runId: string, artifact: SourceArtifact, isolatedText = ""): void {
    const value = SourceArtifactSchema.parse(artifact);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO artifacts
        (id, run_id, provider_id, source_class, url, title, author, language, published_at, observed_at,
         retrieved_at, content_hash, raw_storage_ref, licence, redistribution, trust_metadata_json,
         security_state, isolated_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        runId,
        value.providerId,
        value.sourceClass,
        value.url ?? null,
        value.title ?? null,
        value.author ?? null,
        value.language ?? null,
        value.publishedAt ?? null,
        value.observedAt ?? null,
        value.retrievedAt,
        value.contentHash,
        value.rawStorageRef,
        value.licence ?? null,
        value.redistribution ?? null,
        json(value.trustMetadata),
        value.securityState,
        isolatedText,
      );
    try {
      this.db
        .prepare(
          "INSERT OR REPLACE INTO artifact_search (artifact_id, run_id, title, content) VALUES (?, ?, ?, ?)",
        )
        .run(value.id, runId, value.title ?? "", isolatedText);
    } catch {
      // See the FTS5 migration fallback above.
    }
  }

  listArtifacts(runId: string): SourceArtifact[] {
    return (
      this.db
        .prepare("SELECT * FROM artifacts WHERE run_id = ? ORDER BY retrieved_at")
        .all(runId) as any[]
    ).map((row) =>
      SourceArtifactSchema.parse({
        id: row.id,
        providerId: row.provider_id,
        sourceClass: row.source_class,
        ...(row.url ? { url: row.url } : {}),
        ...(row.title ? { title: row.title } : {}),
        ...(row.author ? { author: row.author } : {}),
        ...(row.language ? { language: row.language } : {}),
        ...(row.published_at ? { publishedAt: row.published_at } : {}),
        ...(row.observed_at ? { observedAt: row.observed_at } : {}),
        retrievedAt: row.retrieved_at,
        contentHash: row.content_hash,
        rawStorageRef: row.raw_storage_ref,
        ...(row.licence ? { licence: row.licence } : {}),
        ...(row.redistribution ? { redistribution: row.redistribution } : {}),
        trustMetadata: parseJson(row.trust_metadata_json),
        securityState: row.security_state,
      }),
    );
  }

  saveEntity(runId: string, entity: Entity): void {
    const value = EntitySchema.parse(entity);
    this.db
      .prepare(
        "INSERT OR REPLACE INTO entities (id, run_id, kind, label, aliases_json, attributes_json, locations_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        value.id,
        runId,
        value.kind,
        value.label,
        json(value.aliases),
        json(value.attributes),
        json(value.locations),
      );
    const aliasStatement = this.db.prepare(
      "INSERT OR IGNORE INTO aliases (entity_id, alias) VALUES (?, ?)",
    );
    for (const alias of value.aliases) aliasStatement.run(value.id, alias);
  }

  listEntities(runId: string): Entity[] {
    return (
      this.db.prepare("SELECT * FROM entities WHERE run_id = ? ORDER BY label").all(runId) as any[]
    ).map((row) =>
      EntitySchema.parse({
        id: row.id,
        kind: row.kind,
        label: row.label,
        aliases: parseJson(row.aliases_json),
        attributes: parseJson(row.attributes_json),
        locations: parseJson(row.locations_json),
      }),
    );
  }

  saveClaim(runId: string, claim: Claim): void {
    const value = ClaimSchema.parse(claim);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO claims
        (id, run_id, artifact_id, subject_json, predicate, object_json, time_json, geography_json,
         evidence_span_json, confidence, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        runId,
        value.artifactId,
        json(value.subject),
        value.predicate,
        json(value.object),
        value.time ? json(value.time) : null,
        value.geography ? json(value.geography) : null,
        value.evidenceSpan ? json(value.evidenceSpan) : null,
        value.confidence,
        value.state,
      );
  }

  listClaims(runId: string): Claim[] {
    return (
      this.db.prepare("SELECT * FROM claims WHERE run_id = ? ORDER BY rowid").all(runId) as any[]
    ).map((row) =>
      ClaimSchema.parse({
        id: row.id,
        artifactId: row.artifact_id,
        subject: parseJson(row.subject_json),
        predicate: row.predicate,
        object: parseJson(row.object_json),
        ...(row.time_json ? { time: parseJson(row.time_json) } : {}),
        ...(row.geography_json ? { geography: parseJson(row.geography_json) } : {}),
        ...(row.evidence_span_json ? { evidenceSpan: parseJson(row.evidence_span_json) } : {}),
        confidence: row.confidence,
        state: row.state,
      }),
    );
  }

  saveSnapshot(runId: string, snapshot: WorldSnapshot): void {
    const value = WorldSnapshotSchema.parse(snapshot);
    this.db
      .prepare(
        "INSERT OR REPLACE INTO snapshots (id, run_id, world_id, as_of, data_json) VALUES (?, ?, ?, ?, ?)",
      )
      .run(value.id, runId, value.worldId, value.asOf, json(value));
  }

  listSnapshots(runId: string): WorldSnapshot[] {
    return (
      this.db
        .prepare("SELECT data_json FROM snapshots WHERE run_id = ? ORDER BY as_of")
        .all(runId) as Array<{ data_json: string }>
    ).map((row) => WorldSnapshotSchema.parse(parseJson(row.data_json)));
  }

  saveWatcher(watcher: Watcher): void {
    const value = WatcherSchema.parse(watcher);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO watchers
        (id, run_id, target_ids_json, query, source_providers_json, cadence, language, geography,
         cursor, last_successful_run, last_material_update, health) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        value.runId,
        json(value.targetIds),
        value.query,
        json(value.sourceProviders),
        value.cadence,
        value.language,
        value.geography,
        value.cursor,
        value.lastSuccessfulRun,
        value.lastMaterialUpdate,
        value.health,
      );
  }

  listWatchers(runId?: string): Watcher[] {
    const rows = runId
      ? (this.db
          .prepare("SELECT * FROM watchers WHERE run_id = ? ORDER BY rowid")
          .all(runId) as any[])
      : (this.db.prepare("SELECT * FROM watchers ORDER BY rowid").all() as any[]);
    return rows.map((row) =>
      WatcherSchema.parse({
        id: row.id,
        runId: row.run_id,
        targetIds: parseJson(row.target_ids_json),
        query: row.query,
        sourceProviders: parseJson(row.source_providers_json),
        cadence: row.cadence,
        language: row.language,
        geography: row.geography,
        cursor: row.cursor,
        lastSuccessfulRun: row.last_successful_run,
        lastMaterialUpdate: row.last_material_update,
        health: row.health,
      }),
    );
  }

  saveEvent(event: ProcessingEvent): void {
    const value = ProcessingEventSchema.parse(event);
    this.db
      .prepare(
        `INSERT OR IGNORE INTO processing_events
        (id, run_id, lane, type, status, label, entity_id, artifact_id, count_delta, created_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        value.runId,
        value.lane,
        value.type,
        value.status,
        value.label,
        value.entityId ?? null,
        value.artifactId ?? null,
        value.countDelta ?? null,
        value.createdAt,
        json(value.metadata),
      );
    for (const listener of this.subscribers.get(value.runId) ?? []) listener(value);
  }

  listEvents(runId: string): ProcessingEvent[] {
    return (
      this.db
        .prepare("SELECT * FROM processing_events WHERE run_id = ? ORDER BY created_at, rowid")
        .all(runId) as any[]
    ).map((row) =>
      ProcessingEventSchema.parse({
        id: row.id,
        runId: row.run_id,
        lane: row.lane,
        type: row.type,
        status: row.status,
        label: row.label,
        ...(row.entity_id ? { entityId: row.entity_id } : {}),
        ...(row.artifact_id ? { artifactId: row.artifact_id } : {}),
        ...(row.count_delta !== null ? { countDelta: row.count_delta } : {}),
        createdAt: row.created_at,
        metadata: parseJson(row.metadata_json),
      }),
    );
  }

  subscribe(runId: string, listener: (event: ProcessingEvent) => void): () => void {
    const listeners = this.subscribers.get(runId) ?? new Set();
    listeners.add(listener);
    this.subscribers.set(runId, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.subscribers.delete(runId);
    };
  }

  saveProtection(runId: string, protection: Protection): void {
    const value = ProtectionSchema.parse(protection);
    this.db
      .prepare("INSERT OR REPLACE INTO protections (id, run_id, data_json) VALUES (?, ?, ?)")
      .run(value.id, runId, json(value));
    if (value.toolProposal) {
      this.db
        .prepare(
          `INSERT OR REPLACE INTO tool_proposals
          (id, run_id, protection_id, tool, arguments_json, status, approval_required)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          value.toolProposal.id,
          runId,
          value.id,
          value.toolProposal.tool,
          json(value.toolProposal.arguments),
          "pending",
          value.toolProposal.approvalRequired ? 1 : 0,
        );
    }
  }

  listProtections(runId: string): Protection[] {
    return (
      this.db
        .prepare("SELECT data_json FROM protections WHERE run_id = ? ORDER BY rowid")
        .all(runId) as Array<{ data_json: string }>
    ).map((row) => ProtectionSchema.parse(parseJson(row.data_json)));
  }

  updateProtectionStatus(
    runId: string,
    protectionId: string,
    status: Protection["status"],
  ): Protection {
    const protection = this.listProtections(runId).find((entry) => entry.id === protectionId);
    if (!protection) throw new Error("Protection not found");
    const updated = ProtectionSchema.parse({ ...protection, status });
    this.saveProtection(runId, updated);
    return updated;
  }

  updateToolProposal(proposalId: string, status: string): void {
    this.db
      .prepare("UPDATE tool_proposals SET status = ?, executed_at = ? WHERE id = ?")
      .run(status, status === "executed" ? new Date().toISOString() : null, proposalId);
  }

  saveEvidence(runId: string, evidence: EvidenceRecord): void {
    const value = EvidenceRecordSchema.parse(evidence);
    this.db
      .prepare("INSERT OR REPLACE INTO evidence (id, run_id, data_json) VALUES (?, ?, ?)")
      .run(value.id, runId, json(value));
  }

  listEvidence(runId: string): EvidenceRecord[] {
    return (
      this.db
        .prepare("SELECT data_json FROM evidence WHERE run_id = ? ORDER BY rowid")
        .all(runId) as Array<{ data_json: string }>
    ).map((row) => EvidenceRecordSchema.parse(parseJson(row.data_json)));
  }

  saveCustomSource(
    runId: string,
    source: JsonRecord & {
      id: string;
      kind: string;
      label: string;
      value: string;
      targetIds: string[];
      enabled: boolean;
    },
  ): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO custom_sources
        (id, run_id, kind, label, value, target_ids_json, mapping_json, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        source.id,
        runId,
        source.kind,
        source.label,
        source.value,
        json(source.targetIds),
        source.mapping ? json(source.mapping) : null,
        source.enabled ? 1 : 0,
      );
  }

  listCustomSources(runId: string): CustomSource[] {
    return (
      this.db
        .prepare("SELECT * FROM custom_sources WHERE run_id = ? ORDER BY rowid")
        .all(runId) as any[]
    ).map((row) => ({
      id: row.id,
      kind: row.kind,
      label: row.label,
      value: row.value,
      targetIds: parseJson<string[]>(row.target_ids_json),
      ...(row.mapping_json ? { mapping: parseJson<Record<string, string>>(row.mapping_json) } : {}),
      enabled: Boolean(row.enabled),
    })) as CustomSource[];
  }

  saveNotificationDestination(destination: NotificationDestination): void {
    const value = NotificationDestinationSchema.parse(destination);
    this.db
      .prepare(
        `INSERT OR REPLACE INTO notification_destinations
        (id, run_id, type, name, destination, target_ids_json, enabled, allow_private_network,
         include_sensitive, simulation_notifications, settings_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        value.runId,
        value.type,
        value.name,
        value.destination,
        json(value.targetIds),
        value.enabled ? 1 : 0,
        value.allowPrivateNetwork ? 1 : 0,
        value.includeSensitive ? 1 : 0,
        value.simulationNotifications ? 1 : 0,
        json(value.settings),
        value.createdAt,
        value.updatedAt,
      );
  }

  listNotificationDestinations(runId: string, includeDisabled = false): NotificationDestination[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM notification_destinations WHERE run_id = ? ${includeDisabled ? "" : "AND enabled = 1"} ORDER BY created_at`,
      )
      .all(runId) as any[];
    return rows.map((row) =>
      NotificationDestinationSchema.parse({
        id: row.id,
        runId: row.run_id,
        type: row.type,
        name: row.name,
        destination: row.destination,
        targetIds: parseJson(row.target_ids_json),
        enabled: Boolean(row.enabled),
        allowPrivateNetwork: Boolean(row.allow_private_network),
        includeSensitive: Boolean(row.include_sensitive),
        simulationNotifications: Boolean(row.simulation_notifications),
        settings: parseJson(row.settings_json),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }),
    );
  }

  deleteNotificationDestination(runId: string, destinationId: string): void {
    this.db
      .prepare("DELETE FROM notification_destinations WHERE run_id = ? AND id = ?")
      .run(runId, destinationId);
  }

  saveNotification(runId: string, fingerprint: string, notification: AgentNotification): boolean {
    const value = AgentNotificationSchema.parse(notification);
    const result = this.db
      .prepare(
        "INSERT OR IGNORE INTO notifications (id, run_id, fingerprint, data_json, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(value.id, runId, fingerprint, json(value), value.createdAt);
    return result.changes === 1;
  }

  hasNotificationFingerprint(runId: string, fingerprint: string): boolean {
    return Boolean(
      this.db
        .prepare("SELECT 1 FROM notifications WHERE run_id = ? AND fingerprint = ?")
        .get(runId, fingerprint),
    );
  }

  listNotifications(runId: string): AgentNotification[] {
    return (
      this.db
        .prepare("SELECT data_json FROM notifications WHERE run_id = ? ORDER BY created_at DESC")
        .all(runId) as Array<{ data_json: string }>
    ).map((row) => AgentNotificationSchema.parse(parseJson(row.data_json)));
  }

  saveNotificationDelivery(runId: string, delivery: NotificationDelivery): void {
    const value = NotificationDeliverySchema.parse(delivery);
    this.db
      .prepare(
        `INSERT INTO notification_deliveries
        (id, run_id, notification_id, destination_id, status, attempted_at, error_code, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        value.id,
        runId,
        value.notificationId,
        value.destinationId,
        value.status,
        value.attemptedAt,
        value.errorCode ?? null,
        value.errorMessage ?? null,
      );
  }

  listNotificationDeliveries(runId: string): NotificationDelivery[] {
    return (
      this.db
        .prepare(
          "SELECT * FROM notification_deliveries WHERE run_id = ? ORDER BY attempted_at DESC",
        )
        .all(runId) as any[]
    ).map((row) =>
      NotificationDeliverySchema.parse({
        id: row.id,
        notificationId: row.notification_id,
        destinationId: row.destination_id,
        status: row.status,
        attemptedAt: row.attempted_at,
        ...(row.error_code ? { errorCode: row.error_code } : {}),
        ...(row.error_message ? { errorMessage: row.error_message } : {}),
      }),
    );
  }

  recentDeliveryCount(destinationId: string, since: string): number {
    const row = this.db
      .prepare(
        "SELECT COUNT(*) AS count FROM notification_deliveries WHERE destination_id = ? AND attempted_at >= ? AND status != 'skipped'",
      )
      .get(destinationId, since) as { count: number };
    return row.count;
  }

  latestLiveRun(): RunRecord | undefined {
    const row = this.db
      .prepare("SELECT id FROM runs WHERE phase = 'live' ORDER BY updated_at DESC LIMIT 1")
      .get() as { id: string } | undefined;
    return row ? this.getRun(row.id) : undefined;
  }

  worldView(runId: string): WorldView {
    const run = this.getRun(runId);
    if (!run) throw new Error("Run not found");
    const events = this.listEvents(runId);
    return {
      runId,
      phase: run.phase,
      demo: run.demo,
      ...(run.demo
        ? { demoDisclosure: "Frozen demonstration data — not a live intelligence feed." }
        : {}),
      targets: this.listTargets(runId),
      artifacts: this.listArtifacts(runId),
      claims: this.listClaims(runId),
      entities: this.listEntities(runId),
      snapshots: this.listSnapshots(runId),
      protections: this.listProtections(runId),
      evidence: this.listEvidence(runId),
      watchers: this.listWatchers(runId),
      events,
      counts: countsFromEvents(events),
    };
  }

  close(): void {
    this.db.close();
  }
}
