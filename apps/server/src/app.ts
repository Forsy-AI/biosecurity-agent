import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import cors from "@fastify/cors";
import multipart from "@fastify/multipart";
import fastifyStatic from "@fastify/static";
import Fastify, { type FastifyInstance } from "fastify";
import pdfParse from "pdf-parse/lib/pdf-parse.js";
import { nanoid } from "nanoid";
import {
  CustomSourceSchema,
  ProcessingEventSchema,
  SourceArtifactSchema,
  StartRunRequestSchema,
  TargetModellingResultSchema,
  TargetSchema,
  type AgentConfig,
  NotificationDestinationInputSchema,
} from "@biosecurity/contracts";
import {
  AnthropicAgentAdapter,
  CodexAgentAdapter,
  MockAgentAdapter,
  OllamaAgentAdapter,
  createAgentAdapter,
} from "@biosecurity/agent-adapters";
import { LiveTracker } from "./local/tracker.js";
import { NotificationService } from "./local/notifications.js";
import { suggestProtection, decideToolProposal } from "./local/protection.js";
import { inspectRunBundle, writeRunBundle } from "./local/replay.js";
import {
  SecretRedactor,
  isolateHtml,
  isolateText,
  safeUploadPath,
  validateDefensiveRequest,
  validateRemoteUrl,
  validateUpload,
} from "@biosecurity/safety";
import { createSimulationPlan, runSimulation } from "./local/simulation.js";
import { INITIAL_SOURCE_MANIFESTS, sourceHealthSummary } from "./local/source-catalog.js";
import { BiosecurityDatabase, createSecretStore, type SecretStore } from "./local/state.js";
import { buildInvestigationPlan, modelTargets } from "./local/targeting.js";
import { buildDeterministicWorld, DEMO_FACTS, pollLiveWatcher } from "./local/world.js";

export type ServerOptions = {
  dataDir?: string;
  memory?: boolean;
  logger?: boolean;
  eventDelayMs?: number;
  serveWeb?: boolean;
  viewerRoot?: string;
};

declare module "fastify" {
  interface FastifyInstance {
    biosecurity: {
      database: BiosecurityDatabase;
      secrets: SecretStore;
      redactor: SecretRedactor;
      tracker: LiveTracker;
      notifications: NotificationService;
      jobs: Set<Promise<void>>;
    };
  }
}

const DEMO_TARGETS = [
  {
    name: "London household",
    description: "A household in London preparing for an upcoming international journey.",
  },
  {
    name: "Milo",
    description: "The household's companion dog in London.",
  },
  {
    name: "Heathrow → Singapore journey",
    description: "An upcoming international journey from London Heathrow to Singapore.",
  },
];

function publicAgentConfig(
  config: AgentConfig,
): Omit<AgentConfig, "apiKey"> & { apiKeyConfigured: boolean } {
  const { apiKey: _, ...safe } = config;
  return { ...safe, apiKeyConfigured: Boolean(config.apiKey) };
}

export async function buildServer(options: ServerOptions = {}): Promise<FastifyInstance> {
  const dataDir = resolve(
    options.dataDir ?? process.env.BIOSECURITY_DATA_DIR ?? ".biosecurity-agent",
  );
  const database = await BiosecurityDatabase.open(dataDir, options.memory ?? false);
  const secrets = createSecretStore(dataDir);
  const redactor = new SecretRedactor();
  const notifications = new NotificationService(database, secrets, redactor);
  for (const run of database.listRuns()) {
    if (run.agentProvider === "mock") notifications.setAgent(run.id, new MockAgentAdapter());
    if (run.agentProvider === "codex") {
      notifications.setAgent(
        run.id,
        new CodexAgentAdapter({
          provider: "codex",
          model: run.agentModel,
          instructions: "Evaluate only material, evidenced tracked-target changes.",
          parameters: {},
        }),
      );
    }
    if (run.agentProvider === "anthropic") {
      notifications.setAgent(
        run.id,
        new AnthropicAgentAdapter(
          {
            provider: "anthropic",
            model: run.agentModel,
            instructions: "Evaluate only material, evidenced tracked-target changes.",
            parameters: {},
          },
          secrets,
          redactor,
        ),
      );
    }
    if (run.agentProvider === "ollama") {
      notifications.setAgent(
        run.id,
        new OllamaAgentAdapter(
          {
            provider: "ollama",
            model: run.agentModel,
            endpoint: "http://127.0.0.1:11434/",
            instructions: "Evaluate only material, evidenced tracked-target changes.",
            parameters: {},
          },
          secrets,
          redactor,
        ),
      );
    }
  }
  const tracker = new LiveTracker(
    database,
    (watcher) => pollLiveWatcher(database, watcher),
    async ({ watcher, snapshot, summary, evidenceIds: liveEvidenceIds }) => {
      let notificationSnapshot = snapshot;
      const world = database.worldView(watcher.runId);
      const liveEvidence = world.evidence.filter(
        (item) => liveEvidenceIds.includes(item.id) && item.status === "observed" && item.material,
      );
      if (liveEvidence.length) {
        const protection = suggestProtection(world.targets, world.claims, liveEvidence, {
          demo: database.getRun(watcher.runId)?.demo ?? false,
        });
        database.saveProtection(watcher.runId, protection);
        notificationSnapshot = {
          ...snapshot,
          protectionIds: [...new Set([...snapshot.protectionIds, protection.id])],
        };
        database.saveSnapshot(watcher.runId, notificationSnapshot);
        database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_${nanoid(10)}`,
            runId: watcher.runId,
            lane: "LIVE WATCH",
            type: "protection.suggested",
            status: "completed",
            label: protection.title,
            createdAt: new Date().toISOString(),
            metadata: { protectionId: protection.id, approvalRequired: true },
          }),
        );
      }
      const evidenceIds = liveEvidenceIds.length
        ? liveEvidenceIds.slice(0, 5)
        : database
            .listEvidence(watcher.runId)
            .slice(0, 3)
            .map((item) => item.id);
      await notifications.evaluateMaterialChange({
        runId: watcher.runId,
        snapshot: notificationSnapshot,
        targetIds: watcher.targetIds,
        summary,
        evidenceIds,
      });
    },
  );
  const app = Fastify({
    logger: options.logger
      ? { redact: ["req.headers.authorization", "req.body.agent.apiKey", "*.apiKey", "*.token"] }
      : false,
    bodyLimit: 6 * 1024 * 1024,
  });
  const jobs = new Set<Promise<void>>();
  app.decorate("biosecurity", { database, secrets, redactor, tracker, notifications, jobs });

  await app.register(cors, {
    origin(origin, callback) {
      if (!origin || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(origin))
        callback(null, true);
      else callback(new Error("Only localhost browser origins are allowed"), false);
    },
    credentials: false,
  });
  await app.register(multipart, {
    limits: { files: 8, fileSize: 20 * 1024 * 1024, fields: 30 },
  });

  app.setErrorHandler((error, _request, reply) => {
    const raw = error as { message?: unknown; statusCode?: unknown };
    const safe = redactor.redact(
      typeof raw.message === "string" ? raw.message : "Unexpected request error",
    ) as string;
    const statusCode =
      typeof raw.statusCode === "number" && raw.statusCode < 500 ? raw.statusCode : 400;
    void reply.status(statusCode).send({ error: safe });
  });

  app.get("/api/health", async () => {
    const [mock, codex, anthropic, ollama] = await Promise.all([
      new MockAgentAdapter().health(),
      new CodexAgentAdapter({
        provider: "codex",
        model: "default",
        instructions: "",
        parameters: {},
      }).health(),
      new AnthropicAgentAdapter(
        {
          provider: "anthropic",
          model: "claude-sonnet-4-6",
          instructions: "",
          parameters: {},
        },
        secrets,
        redactor,
      ).health(),
      new OllamaAgentAdapter(
        {
          provider: "ollama",
          model: "llama3.2",
          endpoint: "http://127.0.0.1:11434/",
          instructions: "",
          parameters: {},
        },
        secrets,
        redactor,
      ).health(),
    ]);
    return {
      status: "ok",
      bindDefault: "127.0.0.1",
      telemetry: false,
      dataDir,
      secretStore: secrets.kind,
      agents: { mock, codex, anthropic, ollama },
      sources: sourceHealthSummary(),
    };
  });

  app.get("/api/providers", async () => ({
    agents: [
      "codex",
      "anthropic",
      "openai",
      "gemini",
      "openrouter",
      "groq",
      "together",
      "deepseek",
      "xai",
      "fireworks",
      "ollama",
      "openai-compatible",
      "custom",
      "mock",
    ],
    sources: INITIAL_SOURCE_MANIFESTS,
  }));
  app.get("/api/runs", async () => database.listRuns());
  app.get("/api/runs/latest", async (_request, reply) => {
    const run = database.latestLiveRun();
    if (!run) return reply.status(404).send({ error: "No live run found" });
    return database.worldView(run.id);
  });
  app.get<{ Params: { runId: string } }>("/api/runs/:runId", async (request) =>
    database.worldView(request.params.runId),
  );

  type SimulationInput = {
    horizon: string;
    targetIds?: string[];
    extraContext?: string;
    seed?: number;
  };

  const persistSimulation = async (runId: string, input: SimulationInput) => {
    const snapshots = database.listSnapshots(runId);
    const baseSnapshot = snapshots.filter((snapshot) => !snapshot.simulation).at(-1);
    if (!baseSnapshot) throw new Error("A live snapshot is required before simulation");
    const plan = createSimulationPlan({ baseSnapshot, ...input });
    const result = runSimulation(plan, baseSnapshot, database.listClaims(runId));
    const isolated = isolateText(JSON.stringify(plan), { simulation: true });
    const simulationArtifactId = `simulation:${result.snapshot.id}`;
    const simulationArtifact = SourceArtifactSchema.parse({
      id: simulationArtifactId,
      providerId: "simulation-engine",
      sourceClass: "custom",
      title: `Simulation plan · ${plan.horizon}`,
      retrievedAt: new Date().toISOString(),
      contentHash: isolated.contentHash,
      rawStorageRef: simulationArtifactId,
      licence: "local run output",
      redistribution: "local only",
      trustMetadata: { simulated: true, seed: plan.seed },
      securityState: "accepted",
    });
    database.saveArtifact(runId, simulationArtifact, isolated.text);
    for (const claim of result.simulatedClaims) database.saveClaim(runId, claim);
    database.saveSnapshot(runId, result.snapshot);
    database.saveEvent(
      ProcessingEventSchema.parse({
        id: `event_${nanoid(10)}`,
        runId,
        lane: "WORLD SYNTHESIS",
        type: "simulation.completed",
        status: "completed",
        label: `Simulation completed · ${plan.horizon} · seed ${plan.seed}`,
        createdAt: new Date().toISOString(),
        metadata: {
          snapshotId: result.snapshot.id,
          baseSnapshotId: baseSnapshot.id,
          seed: plan.seed,
          horizon: plan.horizon,
        },
      }),
    );
    await writeRunBundle(database, runId);
    return result;
  };

  const startRun = async (
    raw: unknown,
    demoOverride = false,
  ): Promise<{ runId: string; agent: ReturnType<typeof publicAgentConfig> }> => {
    const parsed = StartRunRequestSchema.parse({
      ...(raw as object),
      demo: demoOverride || (raw as any)?.demo,
    });
    validateDefensiveRequest(
      `${parsed.targets.map((target) => `${target.name} ${target.description}`).join(" ")} ${parsed.agent.instructions}`,
    );
    const adapter = await createAgentAdapter(parsed.agent, secrets, redactor);
    const health = await adapter.health();
    if (!health.available || (!health.configured && parsed.agent.provider !== "codex"))
      throw new Error(health.message);
    const run = database.createRun(parsed.agent.provider, parsed.agent.model, parsed.demo);
    notifications.setAgent(run.id, adapter);
    for (const source of parsed.customSources) database.saveCustomSource(run.id, source);
    if (parsed.notificationsEnabled) {
      for (const destination of parsed.notificationDestinations)
        await notifications.createDestination(run.id, destination);
    }
    const job = (async () => {
      try {
        const agentResult = await adapter.run({
          operation: "model-targets",
          instructions: parsed.agent.instructions,
          input: { targets: parsed.targets, untrustedContentIncluded: false },
          schemaName: "TargetModellingSummary",
          onProgress: (progress) =>
            database.saveEvent(
              ProcessingEventSchema.parse({
                id: `event_${nanoid(10)}`,
                runId: run.id,
                lane: "TARGET MODELLING",
                type: `agent.${parsed.agent.provider}.${progress.stage}`,
                status:
                  progress.stage === "completed"
                    ? "completed"
                    : progress.stage === "starting" || progress.stage === "thread-started"
                      ? "started"
                      : "progress",
                label: progress.message,
                createdAt: new Date().toISOString(),
                metadata: {
                  provider: parsed.agent.provider,
                  model: parsed.agent.model,
                  operation: "model-targets",
                  elapsedMs: progress.elapsedMs,
                  ...(progress.threadId ? { threadId: progress.threadId } : {}),
                  ...(progress.usage ? { usage: progress.usage } : {}),
                },
              }),
            ),
        });
        const targetModellingResult = TargetModellingResultSchema.safeParse(agentResult.output);
        database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_${nanoid(10)}`,
            runId: run.id,
            lane: "TARGET MODELLING",
            type: `agent.${parsed.agent.provider}.result`,
            status: "completed",
            label: targetModellingResult.success
              ? "Structured target modelling result retained"
              : "Agent result retained; deterministic target fallback required",
            createdAt: new Date().toISOString(),
            metadata: {
              provider: agentResult.provider,
              model: agentResult.model,
              operation: "model-targets",
              latencyMs: agentResult.latencyMs,
              usage: agentResult.usage,
              ...(agentResult.threadId ? { threadId: agentResult.threadId } : {}),
              structuredOutput: targetModellingResult.success
                ? targetModellingResult.data
                : agentResult.output,
              fallback: !targetModellingResult.success,
            },
          }),
        );
        await buildDeterministicWorld({
          runId: run.id,
          targetDrafts: parsed.targets,
          database,
          demo: parsed.demo,
          demoSourceBaseUrl: (() => {
            const address = app.server.address();
            return address && typeof address !== "string"
              ? `http://127.0.0.1:${address.port}`
              : undefined;
          })(),
          eventDelayMs: options.eventDelayMs ?? (parsed.demo ? 65 : 25),
          targetModellingResult: targetModellingResult.success
            ? targetModellingResult.data
            : undefined,
        });
        const world = database.worldView(run.id);
        if (world.evidence.some((item) => item.status === "observed" && item.material)) {
          const protection = suggestProtection(world.targets, world.claims, world.evidence, {
            demo: parsed.demo,
          });
          database.saveProtection(run.id, protection);
          const latest = database.listSnapshots(run.id).at(-1);
          if (latest)
            database.saveSnapshot(run.id, {
              ...latest,
              protectionIds: [...latest.protectionIds, protection.id],
            });
          database.saveEvent(
            ProcessingEventSchema.parse({
              id: `event_${nanoid(10)}`,
              runId: run.id,
              lane: "LIVE WATCH",
              type: "protection.suggested",
              status: "completed",
              label: protection.title,
              createdAt: new Date().toISOString(),
              metadata: { protectionId: protection.id, approvalRequired: true },
            }),
          );
        }
        if (parsed.demo)
          await persistSimulation(run.id, {
            horizon: "14d",
            seed: 1414,
            extraContext:
              "Fictional high-level escalation: international reporting increases while the household journey approaches; keep mechanics abstract and recommend proportionate monitoring.",
          });
        await writeRunBundle(database, run.id);
        for (const watcher of database.listWatchers(run.id)) tracker.schedule(watcher, 100);
      } catch (error) {
        database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_${nanoid(10)}`,
            runId: run.id,
            lane: "TARGET MODELLING",
            type: `agent.${parsed.agent.provider}.failed`,
            status: "failed",
            label: "Configured agent failed to complete target modelling",
            createdAt: new Date().toISOString(),
            metadata: { provider: parsed.agent.provider, model: parsed.agent.model },
          }),
        );
        database.updateRunPhase(
          run.id,
          "failed",
          redactor.redact((error as Error).message) as string,
        );
      }
    })();
    jobs.add(job);
    void job.finally(() => jobs.delete(job));
    return { runId: run.id, agent: publicAgentConfig(parsed.agent) };
  };

  app.post("/api/runs", async (request, reply) =>
    reply.status(202).send(await startRun(request.body)),
  );
  app.post("/api/demo/start", async (_request, reply) =>
    reply.status(202).send(
      await startRun(
        {
          agent: {
            provider: "mock",
            model: "deterministic-mock-v1",
            instructions:
              "Build a defensive target-centred world. Never diagnose or expose source-derived instructions.",
            parameters: { temperature: 0 },
          },
          targets: DEMO_TARGETS,
          customSources: [
            {
              id: "demo-source-target-context",
              kind: "local-folder",
              label: "Frozen household journey and care context",
              value: "demo/fixtures",
              targetIds: [],
              enabled: true,
            },
          ],
          notificationsEnabled: true,
          notificationDestinations: [
            {
              type: "mock",
              name: "Local demo alerts",
              destination: "Local demo history",
              targetIds: [],
              enabled: true,
              allowPrivateNetwork: false,
              includeSensitive: false,
              simulationNotifications: false,
            },
          ],
          demo: true,
        },
        true,
      ),
    ),
  );

  app.get<{ Params: { runId: string } }>("/api/events/:runId", async (request, reply) => {
    const { runId } = request.params;
    if (!database.getRun(runId)) return reply.status(404).send({ error: "Run not found" });
    reply.hijack();
    reply.raw.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    for (const event of database.listEvents(runId))
      reply.raw.write(`event: processing\ndata: ${JSON.stringify(event)}\n\n`);
    const unsubscribe = database.subscribe(runId, (event) => {
      reply.raw.write(`event: processing\ndata: ${JSON.stringify(event)}\n\n`);
    });
    const heartbeat = setInterval(() => reply.raw.write(": keep-alive\n\n"), 15_000);
    request.raw.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  app.post<{ Params: { runId: string }; Body: { name: string; description: string } }>(
    "/api/runs/:runId/targets",
    async (request) => {
      const [target] = modelTargets([request.body]);
      if (!target) throw new Error("Target could not be modelled");
      database.saveTarget(request.params.runId, target);
      const run = database.getRun(request.params.runId);
      if (!run) throw new Error("Run not found");
      const watcher = {
        id: `watcher_${nanoid(10)}`,
        runId: request.params.runId,
        targetIds: [target.id],
        query: buildInvestigationPlan(target)[0]!.query,
        sourceProviders: run.demo
          ? ["demo-official", "demo-science"]
          : ["who-don", "uk-fsa-alerts", "ncbi-entrez"],
        cadence: run.demo ? 300 : 900,
        language: "en",
        geography: target.locations[0]?.label ?? "unspecified",
        cursor: null,
        lastSuccessfulRun: null,
        lastMaterialUpdate: null,
        health: "starting" as const,
      };
      database.saveWatcher(watcher);
      tracker.schedule(watcher, 100);
      const base = database
        .listSnapshots(request.params.runId)
        .filter((snapshot) => !snapshot.simulation)
        .at(-1);
      if (base)
        database.saveSnapshot(request.params.runId, {
          ...base,
          id: `snapshot_${nanoid(12)}`,
          asOf: new Date().toISOString(),
          targetIds: [...base.targetIds, target.id],
          materialChanges: [],
        });
      database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_${nanoid(10)}`,
          runId: request.params.runId,
          lane: "TARGET MODELLING",
          type: "target.modelled",
          status: "completed",
          label: `${target.name} added and modelled`,
          entityId: target.id,
          createdAt: new Date().toISOString(),
          metadata: { userEdited: true },
        }),
      );
      database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_${nanoid(10)}`,
          runId: request.params.runId,
          lane: "LIVE WATCH",
          type: "watcher.created",
          status: "completed",
          label: `Watcher created for ${target.name}`,
          entityId: target.id,
          createdAt: new Date().toISOString(),
          metadata: { userEdited: true },
        }),
      );
      return target;
    },
  );
  app.patch<{
    Params: { runId: string; targetId: string };
    Body: {
      name?: string;
      description?: string;
      inferredKind?: string;
      attributes?: Record<string, unknown>;
      contextArtifacts?: Array<{
        id: string;
        filename: string;
        mediaType: string;
        size: number;
      }>;
    };
  }>("/api/runs/:runId/targets/:targetId", async (request) => {
    const current = database
      .listTargets(request.params.runId)
      .find((target) => target.id === request.params.targetId);
    if (!current) throw new Error("Target not found");
    const [remodelled] = modelTargets([
      {
        id: current.id,
        name: request.body.name ?? current.name,
        description: request.body.description ?? current.description,
      },
    ]);
    if (!remodelled) throw new Error("Target could not be remodelled");
    const updated = TargetSchema.parse({
      ...remodelled,
      attributes: { ...current.attributes, ...remodelled.attributes, ...request.body.attributes },
      relationships: current.relationships,
      contextArtifacts: request.body.contextArtifacts ?? current.contextArtifacts,
      customSourceIds: current.customSourceIds,
      ...(request.body.inferredKind ? { inferredKind: request.body.inferredKind } : {}),
      updatedAt: new Date().toISOString(),
    });
    database.saveTarget(request.params.runId, updated);
    for (const watcher of database
      .listWatchers(request.params.runId)
      .filter((item) => item.targetIds.includes(updated.id))) {
      database.saveWatcher({
        ...watcher,
        query: buildInvestigationPlan(updated)[0]!.query,
        geography: updated.locations[0]?.label ?? "unspecified",
      });
    }
    database.saveEvent(
      ProcessingEventSchema.parse({
        id: `event_${nanoid(10)}`,
        runId: request.params.runId,
        lane: "TARGET MODELLING",
        type: "target.updated",
        status: "completed",
        label: `${updated.name} updated and watchers replanned`,
        entityId: updated.id,
        createdAt: new Date().toISOString(),
        metadata: { userEdited: true },
      }),
    );
    return updated;
  });
  app.delete<{ Params: { runId: string; targetId: string } }>(
    "/api/runs/:runId/targets/:targetId",
    async (request) => {
      database.deleteTarget(request.params.runId, request.params.targetId);
      const base = database
        .listSnapshots(request.params.runId)
        .filter((snapshot) => !snapshot.simulation)
        .at(-1);
      if (base)
        database.saveSnapshot(request.params.runId, {
          ...base,
          id: `snapshot_${nanoid(12)}`,
          asOf: new Date().toISOString(),
          targetIds: base.targetIds.filter((id) => id !== request.params.targetId),
          materialChanges: [],
        });
      return { deleted: true };
    },
  );

  app.get<{ Params: { runId: string } }>("/api/runs/:runId/custom-sources", async (request) =>
    database.listCustomSources(request.params.runId),
  );
  app.post<{ Params: { runId: string } }>(
    "/api/runs/:runId/custom-sources",
    async (request, reply) => {
      const source = CustomSourceSchema.parse(request.body);
      const targets = database.listTargets(request.params.runId);
      for (const targetId of source.targetIds) {
        if (!targets.some((target) => target.id === targetId))
          throw new Error(`Target not found: ${targetId}`);
      }
      if (["url", "domain", "rss", "sitemap", "rest", "graphql", "webhook"].includes(source.kind))
        await validateRemoteUrl(source.value);
      database.saveCustomSource(request.params.runId, source);
      for (const target of targets.filter((item) => source.targetIds.includes(item.id))) {
        database.saveTarget(request.params.runId, {
          ...target,
          customSourceIds: [...new Set([...target.customSourceIds, source.id])],
          updatedAt: new Date().toISOString(),
        });
      }
      for (const watcher of database.listWatchers(request.params.runId)) {
        if (
          source.targetIds.length &&
          !watcher.targetIds.some((targetId) => source.targetIds.includes(targetId))
        )
          continue;
        const updated = {
          ...watcher,
          sourceProviders: [...new Set([...watcher.sourceProviders, `custom:${source.id}`])],
        };
        database.saveWatcher(updated);
        tracker.schedule(updated, 100);
      }
      database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_${nanoid(10)}`,
          runId: request.params.runId,
          lane: "CUSTOM SOURCES",
          type: "source.configured",
          status: "completed",
          label: `${source.label} connected to ${source.targetIds.length || "all"} target${source.targetIds.length === 1 ? "" : "s"}`,
          createdAt: new Date().toISOString(),
          metadata: { sourceId: source.id, kind: source.kind, targetIds: source.targetIds },
        }),
      );
      return reply.status(201).send(source);
    },
  );

  app.post<{ Params: { runId: string } }>("/api/runs/:runId/context", async (request) => {
    const part = await request.file();
    if (!part) throw new Error("A context file is required");
    const buffer = await part.toBuffer();
    validateUpload(part.filename, part.mimetype, buffer.byteLength);
    const uploadDir = join(dataDir, "uploads", request.params.runId);
    await mkdir(uploadDir, { recursive: true, mode: 0o700 });
    const storagePath = safeUploadPath(uploadDir, `${nanoid(8)}-${basename(part.filename)}`);
    await writeFile(storagePath, buffer, { mode: 0o600 });
    let isolated;
    if (part.mimetype.includes("html")) isolated = isolateHtml(buffer.toString("utf8"));
    else if (part.mimetype === "application/pdf")
      isolated = isolateText((await pdfParse(buffer)).text, { parser: "pdf-parse" });
    else if (part.mimetype.startsWith("text/") || part.mimetype === "application/json")
      isolated = isolateText(buffer.toString("utf8"));
    else
      isolated = isolateText(
        "Image context stored locally. No diagnostic interpretation was performed.",
        { image: true },
      );
    const id = `upload_${nanoid(10)}`;
    database.db
      .prepare(
        "INSERT INTO uploaded_context (id, run_id, filename, media_type, size, storage_ref, security_state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        id,
        request.params.runId,
        basename(part.filename),
        part.mimetype,
        buffer.byteLength,
        storagePath,
        isolated.securityState,
        new Date().toISOString(),
      );
    if (isolated.securityState === "quarantined") {
      database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_${nanoid(10)}`,
          runId: request.params.runId,
          lane: "CUSTOM SOURCES",
          type: "evidence.quarantined",
          status: "completed",
          label: `${basename(part.filename)} quarantined after prompt-injection screening`,
          createdAt: new Date().toISOString(),
          metadata: { uploadId: id, findings: isolated.findings },
        }),
      );
    }
    return {
      id,
      filename: basename(part.filename),
      mediaType: part.mimetype,
      size: buffer.byteLength,
      securityState: isolated.securityState,
    };
  });

  app.post("/api/custom-sources/validate", async (request) => {
    const source = CustomSourceSchema.parse(request.body);
    const errors: string[] = [];
    if (["url", "domain", "rss", "sitemap", "rest", "graphql", "webhook"].includes(source.kind)) {
      try {
        await validateRemoteUrl(source.value);
      } catch (error) {
        errors.push((error as Error).message);
      }
    }
    if (
      (source.kind === "rest" || source.kind === "graphql") &&
      source.mapping &&
      !source.mapping.title &&
      !source.mapping.content
    ) {
      errors.push("A JSON mapping must identify at least a title or content field");
    }
    return {
      valid: errors.length === 0,
      errors,
      normalized: { ...source, value: source.value.trim() },
    };
  });

  app.post<{ Params: { runId: string; sourceId: string } }>(
    "/api/webhooks/:runId/:sourceId",
    async (request) => {
      const isolated = isolateText(JSON.stringify(request.body), {
        webhook: true,
        sourceId: request.params.sourceId,
      });
      database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_${nanoid(10)}`,
          runId: request.params.runId,
          lane: "CUSTOM SOURCES",
          type:
            isolated.securityState === "quarantined"
              ? "evidence.quarantined"
              : "feed.item.received",
          status: "completed",
          label:
            isolated.securityState === "quarantined"
              ? "Webhook content quarantined"
              : "Webhook item received and isolated",
          createdAt: new Date().toISOString(),
          metadata: { sourceId: request.params.sourceId, contentHash: isolated.contentHash },
        }),
      );
      return {
        accepted: true,
        securityState: isolated.securityState,
        contentHash: isolated.contentHash,
      };
    },
  );

  app.post<{
    Params: { runId: string };
    Body: SimulationInput;
  }>("/api/runs/:runId/simulations", async (request) =>
    persistSimulation(request.params.runId, request.body),
  );

  app.post<{
    Params: { runId: string; protectionId: string };
    Body: { decision: "approve" | "reject" };
  }>("/api/runs/:runId/protections/:protectionId/decision", async (request) => {
    if (!request.body || !["approve", "reject"].includes(request.body.decision))
      throw new Error("Decision must be approve or reject");
    const result = decideToolProposal(
      database,
      request.params.runId,
      request.params.protectionId,
      request.body.decision,
    );
    database.saveEvent(
      ProcessingEventSchema.parse({
        id: `event_${nanoid(10)}`,
        runId: request.params.runId,
        lane: "LIVE WATCH",
        type: result.executed ? "tool.executed" : "tool.rejected",
        status: "completed",
        label: result.auditMessage,
        createdAt: new Date().toISOString(),
        metadata: {
          protectionId: request.params.protectionId,
          userDecision: request.body.decision,
        },
      }),
    );
    return result;
  });

  app.get<{ Params: { runId: string } }>("/api/runs/:runId/notifications", async (request) => ({
    enabled: database.listNotificationDestinations(request.params.runId).length > 0,
    destinations: database.listNotificationDestinations(request.params.runId, true),
    notifications: database.listNotifications(request.params.runId),
    deliveries: database.listNotificationDeliveries(request.params.runId),
  }));

  app.post<{ Params: { runId: string } }>(
    "/api/runs/:runId/notification-destinations",
    async (request, reply) => {
      const input = NotificationDestinationInputSchema.parse(request.body);
      const destination = await notifications.createDestination(request.params.runId, input);
      return reply.status(201).send(destination);
    },
  );

  app.post<{ Params: { runId: string; destinationId: string } }>(
    "/api/runs/:runId/notification-destinations/:destinationId/test",
    async (request) =>
      notifications.testDestination(request.params.runId, request.params.destinationId),
  );

  app.delete<{ Params: { runId: string; destinationId: string } }>(
    "/api/runs/:runId/notification-destinations/:destinationId",
    async (request) => {
      await notifications.deleteDestination(request.params.runId, request.params.destinationId);
      return { deleted: true };
    },
  );

  app.post<{ Params: { runId: string }; Body: { targetIds?: string[]; summary?: string } }>(
    "/api/runs/:runId/material-change",
    async (request) => {
      const watcher = database.listWatchers(request.params.runId)[0];
      if (!watcher) throw new Error("A watcher is required");
      const safeWatcher = request.body.targetIds?.length
        ? { ...watcher, targetIds: request.body.targetIds }
        : watcher;
      await tracker.persistMaterialUpdate(
        safeWatcher,
        request.body.summary ?? "A new corroborated target-relevant change was persisted.",
      );
      return {
        material: true,
        notifications: database.listNotificationDeliveries(request.params.runId),
      };
    },
  );

  app.post<{ Params: { runId: string } }>("/api/runs/:runId/export", async (request) => ({
    runId: request.params.runId,
    localPath: await writeRunBundle(database, request.params.runId),
    uploaded: false,
  }));
  app.get<{ Params: { runId: string } }>("/api/runs/:runId/replay", async (request) => {
    const path = await writeRunBundle(database, request.params.runId);
    return { ...(await inspectRunBundle(path)), world: database.worldView(request.params.runId) };
  });

  app.get<{ Params: { filename: string } }>("/demo/sources/:filename", async (request, reply) => {
    const fact = DEMO_FACTS.find((item) => item.filename === request.params.filename);
    if (!fact) return reply.status(404).send("Demo source not found");
    reply.type("text/plain; charset=utf-8").header("x-content-type-options", "nosniff");
    return `${fact.title}\n\n${fact.text}\n\nLicence: ${fact.licence}\n`;
  });

  if (options.serveWeb !== false) {
    const webRoot = options.viewerRoot ?? resolve("apps/viewer/dist");
    try {
      await access(join(webRoot, "index.html"));
      await app.register(fastifyStatic, { root: webRoot, prefix: "/" });
      app.setNotFoundHandler(async (request, reply) => {
        if (request.url.startsWith("/api/") || request.url.startsWith("/demo/"))
          return reply.status(404).send({ error: "Not found" });
        return reply.type("text/html").send(await readFile(join(webRoot, "index.html"), "utf8"));
      });
    } catch {
      app.get("/", async (_request, reply) =>
        reply
          .type("text/html")
          .send(
            "<h1>Biosecurity Agent viewer</h1><p>Viewer build not found. Run pnpm dev for local development.</p>",
          ),
      );
    }
  }

  app.addHook("onReady", async () => tracker.start());
  app.addHook("onClose", async () => {
    await tracker.stop();
    await Promise.allSettled(jobs);
    database.close();
  });
  return app;
}

export async function startServer(
  options: ServerOptions & { host?: string; port?: number } = {},
): Promise<FastifyInstance> {
  const host = options.host ?? "127.0.0.1";
  if (host === "0.0.0.0" || host === "::") throw new Error("Wildcard HTTP binds are prohibited");
  const app = await buildServer(options);
  await app.listen({ host, port: options.port ?? 7331 });
  return app;
}
