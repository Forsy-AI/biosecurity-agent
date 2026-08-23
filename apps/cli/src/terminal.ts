import type { ProcessingEvent, WorldView } from "@biosecurity/contracts";

export type NaturalCommand =
  | { type: "help" }
  | { type: "exit" }
  | { type: "open-world" }
  | { type: "status" }
  | { type: "targets" }
  | { type: "add-target"; description: string }
  | { type: "update-target"; query: string; context: string }
  | { type: "remove-target"; query: string }
  | { type: "add-context"; path: string; targetQuery?: string }
  | { type: "add-source"; value: string; targetQuery?: string }
  | { type: "sources" }
  | { type: "simulate"; horizon: string; extraContext?: string }
  | { type: "evidence"; query?: string }
  | { type: "changes" }
  | { type: "protection" }
  | { type: "approve" }
  | { type: "reject" }
  | { type: "notifications" }
  | { type: "unknown"; input: string };

const trimQuotes = (value: string): string => value.trim().replace(/^['"]|['"]$/g, "");

export function parseNaturalCommand(raw: string): NaturalCommand {
  const input = raw.trim();
  const lower = input.toLowerCase();
  if (!input || lower === "help" || lower === "?") return { type: "help" };
  if (["exit", "quit", "stop"].includes(lower)) return { type: "exit" };
  if (/^(open|show) (the )?(world|viewer)$/.test(lower)) return { type: "open-world" };
  if (/^(status|show status)$/.test(lower)) return { type: "status" };
  if (/^(show|list)( what you know about )?(my )?targets$/.test(lower)) return { type: "targets" };
  if (/^(show|list) sources$/.test(lower)) return { type: "sources" };
  if (/^configure notifications?$/.test(lower)) return { type: "notifications" };
  if (/^(approve|run it|yes,? run it)$/.test(lower)) return { type: "approve" };
  if (/^(reject|dismiss|do not run it)$/.test(lower)) return { type: "reject" };
  if (/^(show )?(protection|protections|suggestions)$/.test(lower)) return { type: "protection" };
  if (/what changed|changes since|latest update|most relevant update/.test(lower))
    return { type: "changes" };
  if (/^(show sources|explain|show evidence|evidence)/.test(lower)) {
    return {
      type: "evidence",
      query: input.replace(/^(show sources|show evidence|evidence|explain)s*/i, "") || undefined,
    };
  }

  const simulation = input.match(/^simulate(?:\s+(.*))?$/i);
  if (simulation) {
    const detail = simulation[1]?.trim() ?? "the next 30 days";
    const duration = detail.match(
      /(?:next\s+)?(\d+)\s*(hour|hours|h|day|days|d|week|weeks|w|month|months|m)/i,
    );
    const unit = duration?.[2]?.toLowerCase();
    const horizon = duration
      ? `${duration[1]}${unit?.startsWith("h") ? "h" : unit?.startsWith("w") ? "w" : unit?.startsWith("m") ? "m" : "d"}`
      : "30d";
    return { type: "simulate", horizon, extraContext: detail };
  }

  const context = input.match(/^(?:add|use)\s+(.+?)(?:\s+(?:as context )?(?:to|for)\s+(.+))?$/i);
  if (context && /[/.~\\]/.test(context[1]!)) {
    return { type: "add-context", path: trimQuotes(context[1]!), targetQuery: context[2]?.trim() };
  }

  const source = input.match(
    /^(?:watch|connect|use)\s+(https?:\/\/\S+)(?:\s+(?:for|to)\s+(.+))?$/i,
  );
  if (source) return { type: "add-source", value: source[1]!, targetQuery: source[2]?.trim() };

  const remove = input.match(/^remove\s+(?:the\s+)?(.+?)(?:\s+target)?$/i);
  if (remove) return { type: "remove-target", query: remove[1]!.trim() };

  const add = input.match(/^(?:protect|also protect|add target|target add)\s+(.+)$/i);
  if (add) return { type: "add-target", description: add[1]!.trim() };

  const update = input.match(/^(.+?)\s+(?:is|will be|now has|has)\s+(.+)$/i);
  if (update) return { type: "update-target", query: update[1]!.trim(), context: input };

  return { type: "unknown", input };
}

export type OutputMode = "text" | "json" | "jsonl" | "quiet";

export class TerminalOutput {
  readonly mode: OutputMode;
  readonly color: boolean;
  readonly stream: NodeJS.WriteStream;

  constructor(input: { mode?: OutputMode; stream?: NodeJS.WriteStream; color?: boolean } = {}) {
    this.mode = input.mode ?? "text";
    this.stream = input.stream ?? process.stdout;
    this.color = input.color ?? Boolean(this.stream.isTTY && !process.env.NO_COLOR);
  }

  write(text: string): void {
    if (this.mode === "text") this.stream.write(text);
  }

  line(text = ""): void {
    if (this.mode === "text") this.stream.write(`${text}\n`);
  }

  record(type: string, value: unknown, text?: string): void {
    if (this.mode === "quiet") return;
    if (this.mode === "jsonl") this.stream.write(`${JSON.stringify({ type, value })}\n`);
    else if (this.mode === "json") this.stream.write(`${JSON.stringify(value, null, 2)}\n`);
    else if (text) this.stream.write(`${text}\n`);
  }

  style(text: string, code: number): string {
    return this.color ? `\u001B[${code}m${text}\u001B[0m` : text;
  }
}

export function formatBuildEvent(event: ProcessingEvent, output: TerminalOutput): string {
  const symbol =
    event.status === "failed"
      ? output.style("×", 31)
      : event.status === "completed"
        ? output.style("✓", 32)
        : output.style("→", 36);
  const count = event.countDelta && event.countDelta > 1 ? ` · ${event.countDelta}` : "";
  return `  ${symbol} ${event.label}${count}`;
}

export function buildSummary(world: WorldView): Record<string, unknown> {
  const latest = world.snapshots.at(-1);
  return {
    runId: world.runId,
    phase: world.phase,
    demo: world.demo,
    targets: world.targets.length,
    watchers: world.watchers.filter((watcher) => watcher.health !== "paused").length,
    sources: world.artifacts.length,
    entities: world.entities.length,
    relationships: world.counts["relationships created"] ?? 0,
    targetIntersections: world.counts["target intersections"] ?? 0,
    observedClaims: world.claims.filter((claim) => claim.state === "observed").length,
    updatedAt: latest?.asOf,
  };
}

export function formatLiveHeader(world: WorldView, _output: TerminalOutput): string[] {
  const summary = buildSummary(world);
  return [
    "┌─ LIVE BIOSECURITY ──────────────────────────────────────────┐",
    `│ ${String(summary.targets).padStart(2)} targets · ${String(summary.watchers).padStart(2)} watchers · ${String(summary.sources).padStart(3)} sources · persisted locally`,
    "└──────────────────────────────────────────────────────────────┘",
  ];
}

export function formatTargetStatus(world: WorldView): string[] {
  return world.targets.flatMap((target) => {
    const relevant = world.evidence.filter(
      (item) =>
        item.material && item.targetRelevance.toLowerCase().includes(target.name.toLowerCase()),
    );
    return [
      "",
      target.name.toUpperCase(),
      `  ${relevant.length ? "◐ Changing" : "● Watching"}`,
      `  ${relevant.length ? `${relevant.length} evidence records have explicit target relevance.` : "No new material target change."}`,
    ];
  });
}

export const CLI_HELP = [
  "Natural commands",
  "  protect my dog Milo in London",
  "  Milo is travelling to Cornwall Saturday through Monday",
  "  show what you know about my targets",
  "  watch https://example.org/feed.xml for Milo",
  "  add ~/Documents/context.pdf to Milo",
  "  show sources · what changed · show protection",
  "  simulate the next 30 days",
  "  configure notifications · open world · exit",
].join("\n");
