import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { BiosecurityDatabase } from "./state.js";

const writeJson = async (path: string, value: unknown): Promise<void> =>
  writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
const writeJsonl = async (path: string, values: unknown[]): Promise<void> => {
  await writeFile(path, "", "utf8");
  for (const value of values) await appendFile(path, `${JSON.stringify(value)}\n`, "utf8");
};

export async function writeRunBundle(
  database: BiosecurityDatabase,
  runId: string,
): Promise<string> {
  const run = database.getRun(runId);
  if (!run) throw new Error("Run not found");
  const world = database.worldView(runId);
  const bundleDir = join(database.dataDir, "runs", runId);
  await mkdir(bundleDir, { recursive: true, mode: 0o700 });
  await Promise.all([
    writeJson(join(bundleDir, "manifest.json"), {
      format: "biosecurity-agent-run-bundle/v1",
      runId,
      createdAt: run.createdAt,
      exportedAt: new Date().toISOString(),
      localOnly: true,
      demo: run.demo,
    }),
    writeJson(join(bundleDir, "agent.json"), {
      provider: run.agentProvider,
      model: run.agentModel,
      hiddenReasoningStored: false,
      secretsStored: false,
    }),
    writeJson(join(bundleDir, "targets.json"), world.targets),
    writeJsonl(join(bundleDir, "sources.jsonl"), world.artifacts),
    writeJsonl(join(bundleDir, "claims.jsonl"), world.claims),
    writeJsonl(join(bundleDir, "processing-events.jsonl"), world.events),
    writeJsonl(join(bundleDir, "world-snapshots.jsonl"), world.snapshots),
    writeJsonl(join(bundleDir, "tool-calls.jsonl"), []),
    writeJsonl(join(bundleDir, "protections.jsonl"), world.protections),
    writeJsonl(
      join(bundleDir, "simulation.jsonl"),
      world.snapshots.filter((snapshot) => snapshot.simulation),
    ),
  ]);
  return bundleDir;
}

export async function inspectRunBundle(
  bundleDir: string,
): Promise<{ runId: string; format: string; targets: number; events: number }> {
  const manifest = JSON.parse(await readFile(join(bundleDir, "manifest.json"), "utf8")) as {
    runId: string;
    format: string;
  };
  const targets = JSON.parse(await readFile(join(bundleDir, "targets.json"), "utf8")) as unknown[];
  const eventText = await readFile(join(bundleDir, "processing-events.jsonl"), "utf8");
  return {
    runId: manifest.runId,
    format: manifest.format,
    targets: targets.length,
    events: eventText.split("\n").filter(Boolean).length,
  };
}
