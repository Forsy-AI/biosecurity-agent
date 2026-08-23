#!/usr/bin/env node
import { createInterface, type Interface } from "node:readline/promises";
import { homedir } from "node:os";
import { basename, extname, resolve } from "node:path";
import { readFile, readdir, stat, unlink, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Command, Option } from "commander";
import open from "open";
import { nanoid } from "nanoid";
import type { FastifyInstance, InjectOptions } from "fastify";
import {
  ProcessingEventSchema,
  type AgentConfig,
  type ArtifactRef,
  type NotificationDestinationInput,
  type ProcessingEvent,
  type Target,
  type WorldView,
} from "@biosecurity/contracts";
import {
  buildSummary,
  CLI_HELP,
  formatBuildEvent,
  formatLiveHeader,
  formatTargetStatus,
  parseNaturalCommand,
  TerminalOutput,
  type OutputMode,
} from "./terminal.js";
import { agentConfigForPreset, resolveProviderPreset } from "@biosecurity/agent-adapters";
import { buildServer, startServer } from "../../server/src/app.js";

type GlobalOptions = {
  port: string;
  dataDir: string;
  demo?: boolean;
  headless?: boolean;
  json?: boolean;
  jsonl?: boolean;
  quiet?: boolean;
  verbose?: boolean;
  open?: boolean;
  provider: string;
  model?: string;
  endpoint?: string;
  target: string[];
};

type RunConfig = {
  agent: AgentConfig;
  targets: Array<{ name: string; description: string }>;
  customSources?: Array<Record<string, unknown>>;
  notificationsEnabled?: boolean;
  notificationDestinations?: NotificationDestinationInput[];
  demo?: boolean;
};

const DEFAULT_INSTRUCTIONS =
  "Protect the targets using live, sourced biosecurity intelligence. Track meaningful changes, predict future conditions, and recommend evidence-backed protection.";
const VIEWER_ROOT = fileURLToPath(new URL("../../viewer/dist", import.meta.url));
const collect = (value: string, values: string[]): string[] => [...values, value];

function outputMode(options: GlobalOptions): OutputMode {
  if (options.quiet) return "quiet";
  if (options.jsonl) return "jsonl";
  if (options.json) return "json";
  return "text";
}

function resolvedOptions(command: Command): GlobalOptions {
  return command.optsWithGlobals() as GlobalOptions;
}

function scopedTargetOption(command: Command, direct?: string): string | undefined {
  if (direct) return direct;
  const inherited = command.optsWithGlobals().target;
  if (Array.isArray(inherited)) return inherited.at(-1);
  return typeof inherited === "string" ? inherited : undefined;
}

function sourceKind(url: string): "rss" | "url" {
  const parsed = new URL(url);
  return /(?:rss|feed)/i.test(parsed.pathname) || /\.(?:rss|xml|atom)$/i.test(parsed.pathname)
    ? "rss"
    : "url";
}

function validatePort(raw: string, allowZero = false): number {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < (allowZero ? 0 : 1024) || port > 65_535)
    throw new Error(`Port must be an integer between ${allowZero ? 0 : 1024} and 65535`);
  return port;
}

function terminal(output: TerminalOutput, input = process.stdin): Interface {
  return createInterface({
    input,
    output: output.mode === "text" ? process.stdout : undefined,
    terminal: Boolean(process.stdin.isTTY && output.mode === "text"),
  });
}

const lineIterators = new WeakMap<Interface, AsyncIterator<string>>();

async function ask(
  rl: Interface,
  output: TerminalOutput,
  label: string,
  fallback = "",
): Promise<string> {
  output.write(`${label}${fallback ? ` [${fallback}]` : ""} `);
  let iterator = lineIterators.get(rl);
  if (!iterator) {
    iterator = rl[Symbol.asyncIterator]();
    lineIterators.set(rl, iterator);
  }
  const line = await iterator.next();
  const answer = (line.done ? "" : line.value).trim();
  return answer || fallback;
}

function targetDraft(description: string): { name: string; description: string } {
  const clean = description.trim();
  const first =
    clean
      .split(/\b(?:who|that|based|living|located|travelling|traveling|in|at)\b/i)[0]
      ?.replace(/^(?:my|the)\s+/i, "")
      .trim() || clean;
  const name = first.length > 72 ? `${first.slice(0, 69)}…` : first;
  return { name: name.replace(/^./, (value) => value.toUpperCase()), description: clean };
}

async function request<T>(
  app: FastifyInstance,
  method: NonNullable<InjectOptions["method"]>,
  url: string,
  body?: unknown,
): Promise<T> {
  const options: InjectOptions = { method, url };
  if (body !== undefined) options.payload = body as InjectOptions["payload"];
  const response = await app.inject(options);
  const parsed = response.json() as T & { error?: string };
  if (response.statusCode >= 400)
    throw new Error(parsed.error ?? `${method} ${url} returned HTTP ${response.statusCode}`);
  return parsed;
}

function serverUrl(app: FastifyInstance): string {
  const address = app.server.address();
  if (!address || typeof address === "string")
    throw new Error("Local runtime address is unavailable");
  return `http://127.0.0.1:${address.port}`;
}

async function withEphemeralRuntime<T>(
  options: GlobalOptions,
  task: (app: FastifyInstance) => Promise<T>,
): Promise<T> {
  const app = await startServer({
    port: 0,
    host: "127.0.0.1",
    dataDir: resolve(options.dataDir),
    logger: false,
    serveWeb: false,
  });
  try {
    return await task(app);
  } finally {
    await app.close();
  }
}

async function latestWorld(app: FastifyInstance): Promise<WorldView> {
  return request<WorldView>(app, "GET", "/api/runs/latest");
}

async function optionalLatestWorld(app: FastifyInstance): Promise<WorldView | undefined> {
  const response = await app.inject({ method: "GET", url: "/api/runs/latest" });
  return response.statusCode === 404 ? undefined : (response.json() as WorldView);
}

function banner(output: TerminalOutput): void {
  output.line("┌─ BIOSECURITY AGENT ──────────────────────────────────────┐");
  output.line("│ Open source by Forsy                                    │");
  output.line("└──────────────────────────────────────────────────────────┘");
}

async function onboarding(
  app: FastifyInstance,
  output: TerminalOutput,
): Promise<RunConfig & { contextPaths: string[] }> {
  banner(output);
  output.line();
  output.line(output.style("Configure your AI agent", 1));
  const rl = terminal(output);
  try {
    output.line("  Choose your AI");
    output.line("    1  Codex");
    output.line("    2  Claude / Anthropic");
    output.line("    3  OpenAI");
    output.line("    4  Gemini");
    output.line("    5  OpenRouter");
    output.line("    6  Ollama / Local");
    output.line("    7  Other OpenAI-compatible");
    output.line("    8  Custom endpoint");
    const providerInput = await ask(rl, output, "  ›", "Codex");
    const choices: Record<string, string> = {
      "1": "codex",
      "2": "anthropic",
      "3": "openai",
      "4": "gemini",
      "5": "openrouter",
      "6": "ollama",
      "7": "openai-compatible",
      "8": "custom",
    };
    const providerChoice = choices[providerInput] ?? providerInput;
    const preset = resolveProviderPreset(providerChoice);
    const endpoint = preset.requiresEndpoint
      ? await ask(rl, output, "  Endpoint URL")
      : preset.endpoint;
    const model = ["mock", "ollama"].includes(preset.id)
      ? preset.defaultModel
      : await ask(rl, output, "  Model", preset.defaultModel);
    const agent = agentConfigForPreset(providerChoice, {
      model,
      endpoint,
      instructions: DEFAULT_INSTRUCTIONS,
      parameters: { temperature: 0 },
    });
    output.line(
      `  Status      ${agent.provider === "mock" || agent.provider === "ollama" ? "local adapter selected ✓" : `${preset.secretEnv ?? "provider authentication"} checked when the agent starts`}`,
    );
    output.line();
    output.line(output.style("Agent instructions", 1));
    output.line(
      `  ${DEFAULT_INSTRUCTIONS.match(/.{1,58}(?:\s|$)/g)?.join("\n  ") ?? DEFAULT_INSTRUCTIONS}`,
    );
    output.line();
    output.line(output.style("Targets", 1));
    const descriptions: string[] = [];
    descriptions.push(await ask(rl, output, "  ›", "My family and dog in London"));
    while (true) {
      const next = await ask(rl, output, "  + Add another target (blank to continue)");
      if (!next) break;
      descriptions.push(next);
    }
    const contextPaths: string[] = [];
    const contextPath = await ask(rl, output, "  + Add context file (optional)");
    if (contextPath) contextPaths.push(contextPath);
    const customUrl = await ask(rl, output, "  + Add custom source URL (optional)");
    output.line();
    output.line("Press Enter to start");
    await ask(rl, output, "");
    return {
      agent,
      targets: descriptions.map(targetDraft),
      customSources: customUrl
        ? [
            {
              id: `source_${nanoid(9)}`,
              kind: sourceKind(customUrl),
              label: new URL(customUrl).hostname,
              value: customUrl,
              targetIds: [],
              enabled: true,
            },
          ]
        : [],
      notificationsEnabled: false,
      notificationDestinations: [],
      demo: false,
      contextPaths,
    };
  } finally {
    rl.close();
  }
}

function shouldRenderEvent(event: ProcessingEvent, verbose: boolean): boolean {
  if (verbose) return true;
  return (
    event.status !== "started" ||
    ["world.build.started", "source.search.started"].includes(event.type)
  );
}

async function waitForWorld(
  app: FastifyInstance,
  runId: string,
  output: TerminalOutput,
  verbose = false,
): Promise<WorldView> {
  const database = app.biosecurity.database;
  const seen = new Set<string>();
  const lanes = new Set<string>();
  const emit = (event: ProcessingEvent): void => {
    if (seen.has(event.id)) return;
    seen.add(event.id);
    if (output.mode === "jsonl") output.record("processing-event", event);
    if (output.mode !== "text" || !shouldRenderEvent(event, verbose)) return;
    if (!lanes.has(event.lane)) {
      lanes.add(event.lane);
      output.line();
      output.line(output.style(event.lane.replace("&", "+"), 1));
    }
    output.line(formatBuildEvent(event, output));
  };
  const unsubscribe = database.subscribe(runId, emit);
  for (const event of database.listEvents(runId)) emit(event);
  try {
    while (true) {
      const run = database.getRun(runId);
      if (!run) throw new Error("Run disappeared from local storage");
      if (run.phase === "failed") throw new Error(run.error ?? "World construction failed");
      if (run.phase === "live") {
        for (const event of database.listEvents(runId)) emit(event);
        return database.worldView(runId);
      }
      await new Promise((done) => setTimeout(done, 40));
    }
  } finally {
    unsubscribe();
  }
}

async function createWorld(
  app: FastifyInstance,
  config: RunConfig,
  output: TerminalOutput,
  verbose = false,
): Promise<WorldView> {
  output.line();
  output.line(output.style("BIOSECURITY WORLD BUILD", 36));
  const result = config.demo
    ? await request<{ runId: string }>(app, "POST", "/api/demo/start", {})
    : await request<{ runId: string }>(app, "POST", "/api/runs", config);
  const world = await waitForWorld(app, result.runId, output, verbose);
  if (output.mode === "json")
    output.record("world", { ...buildSummary(world), counts: world.counts });
  else if (output.mode === "text") {
    output.line();
    output.line(output.style("World construction complete", 32));
    const summary = buildSummary(world);
    output.line(
      `  ${summary.entities} entities · ${summary.relationships} relationships · ${summary.targetIntersections} target intersections`,
    );
    output.line(`  ● ${summary.watchers} watchers active`);
  }
  return world;
}

function expandUserPath(value: string): string {
  return resolve(value.startsWith("~/") ? `${homedir()}/${value.slice(2)}` : value);
}

function mediaType(path: string): string {
  const extension = extname(path).toLowerCase();
  if (extension === ".pdf") return "application/pdf";
  if ([".json", ".jsonl"].includes(extension)) return "application/json";
  if ([".html", ".htm"].includes(extension)) return "text/html";
  if ([".png", ".jpg", ".jpeg", ".webp"].includes(extension))
    return `image/${extension === ".jpg" ? "jpeg" : extension.slice(1)}`;
  return "text/plain";
}

async function contextFiles(rawPath: string): Promise<string[]> {
  const path = expandUserPath(rawPath);
  const info = await stat(path);
  if (info.isFile()) return [path];
  if (!info.isDirectory()) throw new Error("Context path must be a file or directory");
  const entries = await readdir(path, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .slice(0, 8)
    .map((entry) => resolve(path, entry.name));
}

async function uploadContext(
  app: FastifyInstance,
  runId: string,
  rawPath: string,
): Promise<Array<ArtifactRef & { securityState: string }>> {
  const results: Array<ArtifactRef & { securityState: string }> = [];
  for (const path of await contextFiles(rawPath)) {
    const form = new FormData();
    form.append(
      "file",
      new Blob([await readFile(path)], { type: mediaType(path) }),
      basename(path),
    );
    const response = await fetch(`${serverUrl(app)}/api/runs/${runId}/context`, {
      method: "POST",
      body: form,
    });
    const body = (await response.json()) as {
      id: string;
      filename: string;
      mediaType: string;
      size: number;
      securityState: string;
      error?: string;
    };
    if (!response.ok)
      throw new Error(body.error ?? `Context upload failed with HTTP ${response.status}`);
    results.push(body);
  }
  return results;
}

async function attachContextToTarget(
  app: FastifyInstance,
  runId: string,
  target: Target,
  files: Array<ArtifactRef & { securityState: string }>,
): Promise<Target> {
  const accepted = files
    .filter((file) => file.securityState === "accepted")
    .map(({ securityState: _securityState, ...artifact }) => artifact);
  if (!accepted.length) return target;
  const existing = new Map(target.contextArtifacts.map((artifact) => [artifact.id, artifact]));
  for (const artifact of accepted) existing.set(artifact.id, artifact);
  return request<Target>(app, "PATCH", `/api/runs/${runId}/targets/${target.id}`, {
    contextArtifacts: [...existing.values()],
  });
}

function findTarget(world: WorldView, query?: string) {
  if (!query) return undefined;
  const lower = query.toLowerCase();
  return world.targets.find(
    (target) =>
      target.name.toLowerCase().includes(lower) ||
      lower.includes(target.name.toLowerCase().split(" ")[0] ?? "___"),
  );
}

function printStatus(world: WorldView, output: TerminalOutput): void {
  const summary = buildSummary(world);
  if (output.mode !== "text") return output.record("status", { ...summary, counts: world.counts });
  for (const line of formatLiveHeader(world, output)) output.line(line);
  for (const line of formatTargetStatus(world)) output.line(line);
  output.line();
  output.line(
    `Observed ${summary.observedClaims} · Simulation snapshots ${world.snapshots.filter((item) => item.simulation).length} · telemetry off`,
  );
}

function printEvidence(world: WorldView, output: TerminalOutput, query?: string): void {
  const lower = query?.toLowerCase();
  const evidence = world.evidence
    .filter(
      (item) =>
        !lower ||
        `${item.sourceTitle} ${item.claim} ${item.targetRelevance}`.toLowerCase().includes(lower),
    )
    .slice(0, 8);
  if (output.mode !== "text") return output.record("evidence", evidence);
  output.line(output.style("EVIDENCE", 36));
  if (!evidence.length) output.line("  No evidence matched that request.");
  for (const item of evidence) {
    output.line(`  [${item.status.toUpperCase()}] ${item.sourceTitle}`);
    output.line(`    ${item.claim}`);
    output.line(
      `    ${Math.round(item.confidence * 100)}% · ${item.sourceClass} · ${item.licenceNotes}`,
    );
  }
}

function printProtection(world: WorldView, output: TerminalOutput): void {
  const protection = [...world.protections].reverse()[0];
  if (output.mode !== "text") return output.record("protection", protection ?? null);
  output.line(output.style("PROTECTION", 36));
  if (!protection) return output.line("  No evidence-backed protection suggestion is available.");
  const targets = world.targets
    .filter((target) => protection.targetIds.includes(target.id))
    .map((target) => target.name)
    .join(", ");
  output.line();
  output.line(targets);
  output.line(`  ${protection.title}`);
  output.line(`  ${protection.summary}`);
  output.line();
  output.line(`Evidence: ${protection.evidenceIds.length} supporting records`);
  output.line(`Uncertainty: ${protection.uncertainty}`);
  if (protection.toolProposal && protection.status === "approval-required") {
    output.line();
    output.line(`Action available: ${protection.toolProposal.expectedEffect}`);
    output.line("Type `approve` to run it or `reject` to dismiss it.");
  }
}

async function configureNotifications(
  app: FastifyInstance,
  world: WorldView,
  output: TerminalOutput,
): Promise<void> {
  const rl = terminal(output);
  try {
    output.line(output.style("NOTIFICATIONS", 36));
    const type = (await ask(
      rl,
      output,
      "  Channel (smtp/webhook/mcp/mock)",
      "mock",
    )) as NotificationDestinationInput["type"];
    const name = await ask(rl, output, "  Name", `${type.toUpperCase()} alerts`);
    let input: NotificationDestinationInput = {
      type,
      name,
      destination: "Local notification history",
      targetIds: [],
      enabled: true,
      allowPrivateNetwork: false,
      includeSensitive: false,
      simulationNotifications: false,
    };
    if (type === "smtp") {
      const host = await ask(rl, output, "  SMTP host");
      const port = Number(await ask(rl, output, "  SMTP port", "587"));
      const from = await ask(rl, output, "  From address");
      const destination = await ask(rl, output, "  Recipient");
      const username = await ask(rl, output, "  Username (optional)");
      const password = await ask(
        rl,
        output,
        "  Password (input is not persisted without BIOSECURITY_MASTER_KEY)",
      );
      input = {
        ...input,
        destination,
        smtp: {
          host,
          port,
          from,
          username: username || undefined,
          password: password || undefined,
          secure: port === 465,
          requireTls: true,
        },
      };
    } else if (type === "webhook") {
      const webhookUrl = await ask(rl, output, "  Webhook URL");
      input = { ...input, destination: new URL(webhookUrl).hostname, webhookUrl };
    } else if (type === "mcp") {
      const serverUrl = await ask(rl, output, "  MCP server URL");
      const toolName = await ask(rl, output, "  Notification tool", "send_notification");
      const bearerToken = await ask(rl, output, "  Bearer token (optional)");
      input = {
        ...input,
        destination: new URL(serverUrl).hostname,
        mcp: { serverUrl, toolName, bearerToken: bearerToken || undefined },
      };
    }
    const destination = await request(
      app,
      "POST",
      `/api/runs/${world.runId}/notification-destinations`,
      input,
    );
    output.record(
      "notification-destination",
      destination,
      `  ✓ ${name} connected. The agent may use only this destination for material tracked-target alerts.`,
    );
  } finally {
    rl.close();
  }
}

async function simulate(
  app: FastifyInstance,
  world: WorldView,
  horizon: string,
  extraContext: string | undefined,
  output: TerminalOutput,
): Promise<WorldView> {
  const base = world.snapshots.filter((item) => !item.simulation).at(-1);
  output.line(output.style("SIMULATION", 35));
  output.line();
  output.line(`Base snapshot       ${base ? new Date(base.asOf).toLocaleString() : "unavailable"}`);
  output.line(`Targets             ${world.targets.length}`);
  output.line(`Horizon             ${horizon}`);
  output.line(`Additional context  ${extraContext || "none"}`);
  output.line("Seed                7331");
  output.line();
  output.line("Advancing a labelled fork of the live world…");
  const result = await request<any>(app, "POST", `/api/runs/${world.runId}/simulations`, {
    horizon,
    targetIds: world.targets.map((target) => target.id),
    extraContext,
    seed: 7331,
  });
  if (output.mode !== "text") output.record("simulation", result);
  else {
    for (const diff of result.diffs as string[]) output.line(`  ◇ ${diff}`);
    output.line(`  ✓ Final simulated snapshot generated · ${result.snapshot.id}`);
  }
  return request<WorldView>(app, "GET", `/api/runs/${world.runId}`);
}

async function handleNatural(
  app: FastifyInstance,
  world: WorldView,
  raw: string,
  output: TerminalOutput,
  viewerUrl: string,
): Promise<{ world: WorldView; exit?: boolean }> {
  const command = parseNaturalCommand(raw);
  if (command.type === "exit") return { world, exit: true };
  if (command.type === "help") output.line(CLI_HELP);
  else if (command.type === "status") printStatus(world, output);
  else if (command.type === "targets") {
    output.record(
      "targets",
      world.targets,
      world.targets
        .map(
          (target) =>
            `  ${target.name} · ${target.inferredKind ?? "unclassified"}\n    ${target.description}`,
        )
        .join("\n"),
    );
  } else if (command.type === "add-target") {
    const target = await request<any>(
      app,
      "POST",
      `/api/runs/${world.runId}/targets`,
      targetDraft(command.description),
    );
    output.record("target", target, `  ✓ ${target.name} added and modelled`);
    world = await request(app, "GET", `/api/runs/${world.runId}`);
  } else if (command.type === "update-target") {
    const target = findTarget(world, command.query);
    if (!target) output.line("  No target matched that description.");
    else {
      const updated = await request<any>(
        app,
        "PATCH",
        `/api/runs/${world.runId}/targets/${target.id}`,
        { description: `${target.description}\n${command.context}` },
      );
      output.record(
        "target",
        updated,
        `  ✓ ${updated.name} updated; location and watcher query remodelled`,
      );
      world = await request(app, "GET", `/api/runs/${world.runId}`);
    }
  } else if (command.type === "remove-target") {
    const target = findTarget(world, command.query);
    if (!target) output.line("  No target matched that description.");
    else {
      await request(app, "DELETE", `/api/runs/${world.runId}/targets/${target.id}`);
      output.line(`  ✓ ${target.name} removed; affected watchers were updated.`);
      world = await request(app, "GET", `/api/runs/${world.runId}`);
    }
  } else if (command.type === "add-context") {
    const target = command.targetQuery ? findTarget(world, command.targetQuery) : undefined;
    if (command.targetQuery && !target) {
      output.line("  No target matched that description; no context was uploaded.");
      return { world, exit: false };
    }
    const files = await uploadContext(app, world.runId, command.path);
    if (target) await attachContextToTarget(app, world.runId, target, files);
    output.record(
      "context",
      files,
      files
        .map(
          (file) =>
            `  ✓ ${file.filename} stored locally · ${file.securityState}${target && file.securityState === "accepted" ? ` · linked to ${target.name}` : ""}`,
        )
        .join("\n"),
    );
    world = await request(app, "GET", `/api/runs/${world.runId}`);
  } else if (command.type === "add-source") {
    const target = findTarget(world, command.targetQuery);
    if (command.targetQuery && !target) {
      output.line("  No target matched that description; no source was connected.");
      return { world, exit: false };
    }
    const source = {
      id: `source_${nanoid(9)}`,
      kind: sourceKind(command.value),
      label: new URL(command.value).hostname,
      value: command.value,
      targetIds: target ? [target.id] : [],
      enabled: true,
    };
    const saved = await request(app, "POST", `/api/runs/${world.runId}/custom-sources`, source);
    output.record(
      "source",
      saved,
      `  ✓ ${source.label} connected to ${target?.name ?? "all targets"}`,
    );
    world = await request(app, "GET", `/api/runs/${world.runId}`);
  } else if (command.type === "sources") {
    const sources = await request<any[]>(app, "GET", `/api/runs/${world.runId}/custom-sources`);
    output.record(
      "sources",
      { artifacts: world.artifacts, custom: sources },
      `  ${world.artifacts.length} persisted artifacts · ${new Set(world.artifacts.map((item) => item.providerId)).size} providers\n${sources.map((source) => `  + ${source.label} · ${source.kind}`).join("\n")}`,
    );
  } else if (command.type === "simulate")
    world = await simulate(app, world, command.horizon, command.extraContext, output);
  else if (command.type === "evidence") printEvidence(world, output, command.query);
  else if (command.type === "changes") {
    const changes = world.snapshots.at(-1)?.materialChanges ?? [];
    output.record(
      "changes",
      changes,
      changes.length
        ? changes.map((item) => `  ${item.significance.toUpperCase()} · ${item.summary}`).join("\n")
        : "  No material changes in the latest snapshot.",
    );
  } else if (command.type === "protection") printProtection(world, output);
  else if (command.type === "approve" || command.type === "reject") {
    const protection = [...world.protections]
      .reverse()
      .find((item) => item.status === "approval-required");
    if (!protection) output.line("  No tool proposal is waiting for approval.");
    else {
      const result = await request<any>(
        app,
        "POST",
        `/api/runs/${world.runId}/protections/${protection.id}/decision`,
        { decision: command.type === "approve" ? "approve" : "reject" },
      );
      output.record("tool-decision", result, `  ${result.auditMessage}`);
      world = await request(app, "GET", `/api/runs/${world.runId}`);
    }
  } else if (command.type === "notifications") await configureNotifications(app, world, output);
  else if (command.type === "open-world") {
    output.line(`  Visual viewer: ${viewerUrl}`);
    await open(viewerUrl);
  } else {
    const adapter = app.biosecurity.notifications.adapters.get(world.runId);
    if (!adapter)
      output.line(
        "  I could not map that request to a safe local operation. Type `help` for examples.",
      );
    else {
      const response = await adapter.run<any, Record<string, unknown>>({
        operation: "conversation",
        instructions:
          "Answer the user's defensive biosecurity world question from the supplied persisted summary. Never diagnose.",
        input: {
          request: command.input,
          world: buildSummary(world),
          evidence: world.evidence.slice(0, 5).map((item) => ({
            id: item.id,
            claim: item.claim,
            targetRelevance: item.targetRelevance,
          })),
        },
        schemaName: "AgentConversationResponse",
        onProgress: (progress) =>
          app.biosecurity.database.saveEvent(
            ProcessingEventSchema.parse({
              id: `event_agent_${nanoid(10)}`,
              runId: world.runId,
              lane: "WORLD SYNTHESIS",
              type: `agent.conversation.${progress.stage}`,
              status:
                progress.stage === "completed"
                  ? "completed"
                  : progress.stage === "starting" || progress.stage === "thread-started"
                    ? "started"
                    : "progress",
              label: progress.message,
              createdAt: new Date().toISOString(),
              metadata: {
                operation: "conversation",
                elapsedMs: progress.elapsedMs,
                ...(progress.threadId ? { threadId: progress.threadId } : {}),
                ...(progress.usage ? { usage: progress.usage } : {}),
              },
            }),
          ),
      });
      app.biosecurity.database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_agent_${nanoid(10)}`,
          runId: world.runId,
          lane: "WORLD SYNTHESIS",
          type: "agent.conversation.result",
          status: "completed",
          label: "Structured conversation result retained",
          createdAt: new Date().toISOString(),
          metadata: {
            provider: response.provider,
            model: response.model,
            operation: "conversation",
            latencyMs: response.latencyMs,
            usage: response.usage,
            ...(response.threadId ? { threadId: response.threadId } : {}),
            structuredOutput: response.output,
          },
        }),
      );
      output.record(
        "agent-response",
        response.output,
        `  ${typeof response.output.summary === "string" ? response.output.summary : JSON.stringify(response.output)}`,
      );
    }
  }
  return { world };
}

async function liveSession(
  app: FastifyInstance,
  initial: WorldView,
  output: TerminalOutput,
  viewerUrl: string,
): Promise<void> {
  let world = initial;
  if (output.mode === "text") {
    output.line();
    printStatus(world, output);
    output.line();
    output.line("Agent");
    output.line("  Monitoring all targets continuously. Type `help` for natural commands.");
  }
  const unsubscribe = app.biosecurity.database.subscribe(world.runId, (event) => {
    if (!shouldRenderEvent(event, false) || event.type === "watcher.tick") return;
    if (output.mode === "jsonl") output.record("live-event", event);
    else if (output.mode === "text") {
      const time = new Date(event.createdAt).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
      output.line(
        `\n${time}  ${(event.lane.split(" ")[0] ?? event.lane).padEnd(9)} ${event.label}`,
      );
    }
  });
  const rl = terminal(output);
  try {
    while (output.mode === "text" && !process.stdin.destroyed) {
      let line: string;
      try {
        line = await ask(rl, output, output.style("\n› ", 36));
      } catch {
        break;
      }
      const result = await handleNatural(app, world, line, output, viewerUrl);
      world = result.world;
      if (result.exit) break;
    }
  } finally {
    unsubscribe();
    rl.close();
  }
}

async function loadRunConfig(path: string): Promise<RunConfig> {
  const text = await readFile(resolve(path), "utf8");
  if (path.endsWith(".json")) return JSON.parse(text) as RunConfig;
  const targets: Array<{ name: string; description: string }> = [];
  let provider = "mock";
  let model: string | undefined;
  let endpoint: string | undefined;
  let current: Partial<{ name: string; description: string }> | undefined;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const pair = line.replace(/^-\s*/, "").match(/^([\w-]+):\s*["']?(.*?)["']?$/);
    if (!pair) continue;
    const key = pair[1]!;
    const value = pair[2]!;
    if (key === "provider") provider = value;
    else if (key === "model") model = value;
    else if (key === "endpoint") endpoint = value;
    else if (key === "name") {
      if (current?.name)
        targets.push({ name: current.name, description: current.description ?? current.name });
      current = { name: value };
    } else if (key === "description" && current) current.description = value;
  }
  if (current?.name)
    targets.push({ name: current.name, description: current.description ?? current.name });
  if (!targets.length) throw new Error("YAML config must contain at least one target with a name");
  return {
    agent: agentConfigForPreset(provider, {
      model,
      endpoint,
      instructions: DEFAULT_INSTRUCTIONS,
      parameters: { temperature: 0 },
    }),
    targets,
    customSources: [],
    notificationsEnabled: false,
    notificationDestinations: [],
    demo: false,
  };
}

async function writeRuntimeFile(
  dataDir: string,
  value: { pid: number; port: number; runId?: string },
): Promise<void> {
  await writeFile(
    resolve(dataDir, "runtime.json"),
    JSON.stringify({ ...value, startedAt: new Date().toISOString() }, null, 2),
    { mode: 0o600 },
  );
}

async function removeRuntimeFile(dataDir: string): Promise<void> {
  await unlink(resolve(dataDir, "runtime.json")).catch(() => undefined);
}

async function runPrimary(options: GlobalOptions, _explicitStart = false): Promise<void> {
  const output = new TerminalOutput({ mode: outputMode(options) });
  const dataDir = resolve(options.dataDir);
  const port = validatePort(options.port);
  const app = await startServer({
    port,
    host: "127.0.0.1",
    dataDir,
    logger: options.verbose ?? false,
    serveWeb: true,
    viewerRoot: VIEWER_ROOT,
  });
  const viewerUrl = `http://127.0.0.1:${port}`;
  let world: WorldView | undefined;
  const close = async (): Promise<void> => {
    await removeRuntimeFile(dataDir);
    await app.close();
  };
  process.once("SIGINT", () => void close().then(() => process.exit(0)));
  process.once("SIGTERM", () => void close().then(() => process.exit(0)));
  try {
    if (options.demo)
      world = await createWorld(
        app,
        {
          agent: {
            provider: "mock",
            model: "deterministic-mock-v1",
            instructions: DEFAULT_INSTRUCTIONS,
            parameters: { temperature: 0 },
          },
          targets: [],
          demo: true,
        },
        output,
        options.verbose,
      );
    else if (options.target.length) {
      const agent = agentConfigForPreset(options.provider, {
        model: options.model,
        endpoint: options.endpoint,
        instructions: DEFAULT_INSTRUCTIONS,
        parameters: { temperature: 0 },
      });
      world = await createWorld(
        app,
        {
          agent,
          targets: options.target.map(targetDraft),
          customSources: [],
          notificationsEnabled: false,
          notificationDestinations: [],
          demo: false,
        },
        output,
        options.verbose,
      );
    } else world = await optionalLatestWorld(app);
    if (!world) {
      if (options.headless)
        throw new Error(
          "No persisted world exists. Supply --target, --demo, or a config file on first headless launch.",
        );
      const config = await onboarding(app, output);
      world = await createWorld(app, config, output, options.verbose);
      for (const path of config.contextPaths) {
        const files = await uploadContext(app, world.runId, path);
        for (const target of world.targets)
          await attachContextToTarget(app, world.runId, target, files);
        output.record(
          "context",
          files,
          files
            .map((file) => `  ✓ ${file.filename} stored locally · ${file.securityState}`)
            .join("\n"),
        );
      }
    } else if (!options.demo && !options.target.length && output.mode === "text") {
      output.line(
        `Restored persisted world ${world.runId} · ${world.targets.length} targets · ${world.watchers.length} watchers`,
      );
    }
    await writeRuntimeFile(dataDir, { pid: process.pid, port, runId: world.runId });
    if (options.headless) {
      output.record(
        "headless-ready",
        buildSummary(world),
        output.mode === "text"
          ? `HEADLESS TRACKING\n  ${world.targets.length} targets · ${world.watchers.length} watchers · viewer not required`
          : undefined,
      );
      const unsubscribe = app.biosecurity.database.subscribe(world.runId, (event) => {
        if (!shouldRenderEvent(event, options.verbose ?? false) || event.type === "watcher.tick")
          return;
        if (output.mode === "jsonl") output.record("live-event", event);
        else if (output.mode === "text")
          output.line(
            `${new Date(event.createdAt).toISOString()}  ${event.lane.split(" ")[0] ?? event.lane}  ${event.label}`,
          );
      });
      try {
        await new Promise<void>(() => undefined);
      } finally {
        unsubscribe();
      }
    } else if (output.mode === "text") await liveSession(app, world, output, viewerUrl);
    else if (output.mode === "jsonl") output.record("world", buildSummary(world));
    else if (output.mode === "json" && !options.demo && !options.target.length)
      output.record("world", buildSummary(world));
  } finally {
    await close();
  }
}

async function doctor(options: GlobalOptions): Promise<void> {
  const output = new TerminalOutput({ mode: outputMode(options) });
  const app = await buildServer({
    dataDir: resolve(options.dataDir),
    logger: false,
    serveWeb: false,
  });
  try {
    const health = await request<any>(app, "GET", "/api/health");
    if (output.mode !== "text") return output.record("doctor", health);
    output.line("Biosecurity Agent doctor");
    output.line(`Local bind: ${health.bindDefault}`);
    output.line(`Secret store: ${health.secretStore}`);
    for (const [name, result] of Object.entries(health.agents as Record<string, any>))
      output.line(
        `Agent ${name}: ${result.available ? "available" : "unavailable"} — ${result.message}`,
      );
    const available = (health.sources as any[]).filter(
      (source) => source.health === "available",
    ).length;
    output.line(
      `Sources: ${available}/${health.sources.length} adapters currently available; others report feature status`,
    );
  } finally {
    await app.close();
  }
}

const program = new Command();
program
  .name("biosecurity-agent")
  .description("Terminal-native target-centred biosecurity intelligence agent")
  .version("0.1.2")
  .option("--port <port>", "localhost viewer/API port", "7331")
  .option("--data-dir <path>", "local application data directory", ".biosecurity-agent")
  .option("--demo", "build the frozen no-key demonstration")
  .option("--headless", "run long-lived tracking without a browser or prompt")
  .option("--json", "emit a JSON result")
  .option("--jsonl", "stream machine-readable JSON Lines")
  .option("--quiet", "suppress non-error output")
  .option("--verbose", "show provider, tool, and all processing events")
  .option("--no-open", "do not open the optional viewer", true)
  .addOption(
    new Option("--provider <provider>", "agent provider")
      .choices([
        "mock",
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
      ])
      .default("mock"),
  )
  .option("--model <model>", "agent model")
  .option("--endpoint <url>", "custom or compatible agent endpoint")
  .option(
    "--target <description>",
    "target description; repeat for multiple targets",
    collect,
    [] as string[],
  )
  .action(async (_options, command) => runPrimary(resolvedOptions(command)));

program
  .command("start")
  .description("start or restore the interactive agent")
  .action(async (_options, command) => runPrimary(resolvedOptions(command), true));
program
  .command("doctor")
  .description("check local agent, source, and storage health")
  .action(async (_options, command) => doctor(resolvedOptions(command)));

const target = program.command("target").description("manage tracked targets");
target
  .command("list")
  .description("list tracked targets")
  .action(async (_options, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const output = new TerminalOutput({ mode: outputMode(resolvedOptions(command)) });
      const world = await latestWorld(app);
      output.record(
        "targets",
        world.targets,
        world.targets
          .map((item) => `${item.id}\t${item.name}\t${item.inferredKind ?? "unknown"}`)
          .join("\n"),
      );
    }),
  );
target
  .command("add [description]")
  .description("add and model a target")
  .action(async (description: string | undefined, _options, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const options = resolvedOptions(command);
      const output = new TerminalOutput({ mode: outputMode(options) });
      const world = await latestWorld(app);
      let value = description;
      if (!value) {
        const rl = terminal(output);
        try {
          value = await ask(rl, output, "Target ›");
        } finally {
          rl.close();
        }
      }
      if (!value) throw new Error("A target description is required");
      const saved = await request(
        app,
        "POST",
        `/api/runs/${world.runId}/targets`,
        targetDraft(value),
      );
      output.record("target", saved, `Target added to ${world.runId}`);
    }),
  );

const source = program.command("source").description("manage custom intelligence sources");
source
  .command("add <url>")
  .option("--target <query>", "attach to a matching target")
  .description("connect a URL or feed")
  .action(async (url: string, local: { target?: string }, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const options = resolvedOptions(command);
      const output = new TerminalOutput({ mode: outputMode(options) });
      const world = await latestWorld(app);
      const targetQuery = scopedTargetOption(command, local.target);
      const selected = findTarget(world, targetQuery);
      if (targetQuery && !selected)
        throw new Error(
          `No target matched ${JSON.stringify(targetQuery)}; no source was connected.`,
        );
      const saved = await request(app, "POST", `/api/runs/${world.runId}/custom-sources`, {
        id: `source_${nanoid(9)}`,
        kind: sourceKind(url),
        label: new URL(url).hostname,
        value: url,
        targetIds: selected ? [selected.id] : [],
        enabled: true,
      });
      output.record("source", saved, `Source connected to ${selected?.name ?? "all targets"}`);
    }),
  );

const context = program.command("context").description("manage local target context");
context
  .command("add <path>")
  .option("--target <query>", "link accepted context to one target")
  .description("attach a local file or directory")
  .action(async (path: string, local: { target?: string }, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const options = resolvedOptions(command);
      const output = new TerminalOutput({ mode: outputMode(options) });
      const world = await latestWorld(app);
      const targetQuery = scopedTargetOption(command, local.target);
      const target = targetQuery ? findTarget(world, targetQuery) : undefined;
      if (targetQuery && !target)
        throw new Error(
          `No target matched ${JSON.stringify(targetQuery)}; no context was uploaded.`,
        );
      const files = await uploadContext(app, world.runId, path);
      if (target) await attachContextToTarget(app, world.runId, target, files);
      output.record(
        "context",
        files,
        files
          .map(
            (item) =>
              `${item.filename}\t${item.securityState}${target && item.securityState === "accepted" ? `\tlinked to ${target.name}` : ""}`,
          )
          .join("\n"),
      );
    }),
  );

program
  .command("simulate")
  .option("--horizon <duration>", "simulation horizon", "30d")
  .description("fork the live world into a labelled simulation")
  .action(async (local: { horizon: string }, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const options = resolvedOptions(command);
      const output = new TerminalOutput({ mode: outputMode(options) });
      await simulate(app, await latestWorld(app), local.horizon, undefined, output);
    }),
  );
program
  .command("status")
  .description("show persisted live status")
  .action(async (_options, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) =>
      printStatus(
        await latestWorld(app),
        new TerminalOutput({ mode: outputMode(resolvedOptions(command)) }),
      ),
    ),
  );
program
  .command("notifications")
  .command("setup")
  .description("connect SMTP, webhook, MCP, or local notifications")
  .action(async (_options, command) =>
    withEphemeralRuntime(resolvedOptions(command), async (app) => {
      const options = resolvedOptions(command);
      await configureNotifications(
        app,
        await latestWorld(app),
        new TerminalOutput({ mode: outputMode(options) }),
      );
    }),
  );
program
  .command("run <config>")
  .description("run targets from a JSON or simple YAML config")
  .action(async (config: string, _options, command) => {
    const options = resolvedOptions(command);
    const output = new TerminalOutput({ mode: outputMode(options) });
    const app = await startServer({
      port: validatePort(options.port),
      host: "127.0.0.1",
      dataDir: resolve(options.dataDir),
      logger: options.verbose ?? false,
      serveWeb: false,
    });
    try {
      const world = await createWorld(app, await loadRunConfig(config), output, options.verbose);
      if (options.headless) await new Promise<void>(() => undefined);
      else if (output.mode !== "json") printStatus(world, output);
    } finally {
      await app.close();
    }
  });
program
  .command("view")
  .description("open the optional visual world viewer")
  .action(async (_options, command) => {
    const options = resolvedOptions(command);
    const port = validatePort(options.port);
    const app = await startServer({
      port,
      host: "127.0.0.1",
      dataDir: resolve(options.dataDir),
      logger: options.verbose ?? false,
      serveWeb: true,
      viewerRoot: VIEWER_ROOT,
    });
    const url = `http://127.0.0.1:${port}`;
    process.stdout.write(
      `Visual viewer: ${url}\nThe terminal remains the controller. Press Ctrl-C to close the viewer.\n`,
    );
    if (options.open !== false) await open(url);
    const close = async () => {
      await app.close();
      process.exit(0);
    };
    process.once("SIGINT", () => void close());
    process.once("SIGTERM", () => void close());
  });
program
  .command("stop")
  .description("stop the foreground runtime recorded for this data directory")
  .action(async (_options, command) => {
    const options = resolvedOptions(command);
    const path = resolve(options.dataDir, "runtime.json");
    try {
      const state = JSON.parse(await readFile(path, "utf8")) as { pid: number };
      if (!Number.isInteger(state.pid) || state.pid <= 1 || state.pid === process.pid)
        throw new Error("Runtime PID is invalid");
      process.kill(state.pid, "SIGTERM");
      await unlink(path).catch(() => undefined);
      process.stdout.write(`Stop signal sent to runtime ${state.pid}.\n`);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT")
        process.stdout.write("No recorded Biosecurity Agent runtime is active.\n");
      else throw error;
    }
  });

export async function runCli(argv = process.argv): Promise<void> {
  await program.parseAsync(argv);
}

try {
  await runCli();
} catch (error) {
  process.stderr.write(`Biosecurity Agent: ${(error as Error).message}\n`);
  process.exitCode = 1;
  // Some provider SDKs may retain background handles after an unsuccessful
  // subprocess turn. Preserve graceful cleanup above, then bound fatal exit.
  setTimeout(() => process.exit(1), 100).unref();
}
