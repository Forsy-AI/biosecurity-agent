import { access } from "node:fs/promises";
import { beforeEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({
  hold: false,
  prompt: "",
  threadOptions: undefined as Record<string, unknown> | undefined,
  turnOptions: undefined as { signal?: AbortSignal; outputSchema?: unknown } | undefined,
}));

vi.mock("@openai/codex-sdk", () => ({
  Codex: class {
    startThread(options: Record<string, unknown>) {
      sdk.threadOptions = options;
      const thread = {
        id: null as string | null,
        async runStreamed(
          prompt: string,
          turnOptions: { signal?: AbortSignal; outputSchema?: unknown },
        ) {
          sdk.prompt = prompt;
          sdk.turnOptions = turnOptions;
          return {
            events: (async function* () {
              thread.id = "thread_test";
              yield { type: "thread.started", thread_id: thread.id };
              yield { type: "turn.started" };
              if (sdk.hold)
                await new Promise<void>((resolve, reject) => {
                  if (turnOptions.signal?.aborted) reject(turnOptions.signal.reason);
                  turnOptions.signal?.addEventListener(
                    "abort",
                    () => reject(turnOptions.signal?.reason),
                    { once: true },
                  );
                });
              yield {
                type: "item.completed",
                item: {
                  id: "message_test",
                  type: "agent_message",
                  text: JSON.stringify({
                    summary: "Structured target summary",
                    targets: [
                      {
                        index: 0,
                        inferredKind: "plant",
                        locations: [
                          {
                            label: "Kent, United Kingdom",
                            latitude: 51.2787,
                            longitude: 0.5217,
                            resolution: "region",
                          },
                        ],
                      },
                    ],
                  }),
                },
              };
              yield {
                type: "turn.completed",
                usage: {
                  input_tokens: 12,
                  cached_input_tokens: 0,
                  cache_write_input_tokens: 0,
                  output_tokens: 4,
                  reasoning_output_tokens: 0,
                },
              };
            })(),
          };
        },
      };
      return thread;
    }

    resumeThread(_id: string, options: Record<string, unknown>) {
      return this.startThread(options);
    }
  },
}));

import { CodexAgentAdapter, type AgentProgress } from "@biosecurity/agent-adapters";

describe("Codex adapter hardening", () => {
  beforeEach(() => {
    sdk.hold = false;
    sdk.prompt = "";
    sdk.threadOptions = undefined;
    sdk.turnOptions = undefined;
  });

  it("streams a structured turn in an isolated read-only workspace", async () => {
    const progress: AgentProgress[] = [];
    const adapter = new CodexAgentAdapter({
      provider: "codex",
      model: "gpt-test",
      instructions: "Use persisted evidence only.",
      parameters: { timeoutMs: 30_000 },
    });
    const response = await adapter.run({
      operation: "model-targets",
      instructions: "Use persisted evidence only.",
      input: { targets: [{ name: "Tomatoes", description: "Tomatoes in Kent" }] },
      schemaName: "TargetModellingSummary",
      onProgress: (event) => progress.push(event),
    });

    expect(response).toMatchObject({
      provider: "codex",
      model: "gpt-test",
      threadId: "thread_test",
      output: {
        summary: "Structured target summary",
        targets: [{ index: 0, inferredKind: "plant" }],
      },
      usage: { inputTokens: 12, outputTokens: 4 },
      rawStored: false,
    });
    expect(sdk.threadOptions).toMatchObject({
      model: "gpt-test",
      sandboxMode: "read-only",
      skipGitRepoCheck: true,
      modelReasoningEffort: "low",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      approvalPolicy: "never",
    });
    expect(sdk.prompt).toContain("Complete only this narrow structured-analysis step.");
    expect(sdk.prompt).toContain("Do not inspect files, run commands, browse, call tools");
    expect(sdk.turnOptions?.outputSchema).toMatchObject({
      required: ["summary", "targets"],
      additionalProperties: false,
    });
    expect(progress.map((event) => event.stage)).toEqual([
      "starting",
      "thread-started",
      "submitted",
      "response",
      "completed",
    ]);
    await expect(access(String(sdk.threadOptions?.workingDirectory))).rejects.toThrow();
  });

  it("propagates cancellation and cleans up the isolated workspace", async () => {
    sdk.hold = true;
    const controller = new AbortController();
    const adapter = new CodexAgentAdapter({
      provider: "codex",
      model: "default",
      instructions: "Use persisted evidence only.",
      parameters: { timeoutMs: 30_000 },
    });
    const running = adapter.run({
      operation: "model-targets",
      instructions: "Use persisted evidence only.",
      input: { targets: [{ name: "Tomatoes", description: "Tomatoes in Kent" }] },
      schemaName: "TargetModellingSummary",
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(new Error("operator cancelled Codex")), 5);

    await expect(running).rejects.toThrow("operator cancelled Codex");
    expect(sdk.threadOptions).not.toHaveProperty("model");
    await expect(access(String(sdk.threadOptions?.workingDirectory))).rejects.toThrow();
  });
});
