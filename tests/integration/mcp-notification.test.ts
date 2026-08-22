import { beforeEach, describe, expect, it, vi } from "vitest";

const callTool = vi.fn(async (_input: unknown) => ({ content: [{ type: "text", text: "sent" }] }));
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: class {
    async connect() {}
    async listTools() {
      return { tools: [{ name: "send_notification" }] };
    }
    callTool = callTool;
    async close() {}
  },
}));
vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: class {},
}));

import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockAgentAdapter } from "@biosecurity/agent-adapters";
import { NotificationService } from "../../apps/server/src/local/notifications.js";
import { BiosecurityDatabase, MemorySecretStore } from "../../apps/server/src/local/state.js";
import { buildDeterministicWorld } from "../../apps/server/src/local/world.js";

describe("MCP notification channel", () => {
  beforeEach(() => callTool.mockClear());

  it("calls only the exact configured notification tool with state-derived content", async () => {
    const database = await BiosecurityDatabase.open(
      await mkdtemp(join(tmpdir(), "biosecurity-mcp-")),
      true,
    );
    try {
      const run = database.createRun("mock", "deterministic-mock-v1", true);
      await buildDeterministicWorld({
        runId: run.id,
        targetDrafts: [{ name: "Tomato plants", description: "Hackney" }],
        database,
        demo: true,
        eventDelayMs: 0,
      });
      const service = new NotificationService(database, new MemorySecretStore());
      service.setAgent(run.id, new MockAgentAdapter());
      await service.createDestination(run.id, {
        type: "mcp",
        name: "Mock MCP",
        destination: "Test messaging tool",
        targetIds: [],
        enabled: true,
        allowPrivateNetwork: true,
        mcp: { serverUrl: "http://127.0.0.1:9911/mcp", toolName: "send_notification" },
      });
      const deliveries = await service.evaluateMaterialChange({
        runId: run.id,
        snapshot: database.listSnapshots(run.id).at(-1)!,
        targetIds: [database.listTargets(run.id)[0]!.id],
        summary: "A material plant-health change was persisted.",
        evidenceIds: database
          .listEvidence(run.id)
          .slice(0, 2)
          .map((item) => item.id),
      });
      expect(deliveries[0]?.status).toBe("sent");
      expect(callTool).toHaveBeenCalledOnce();
      expect(callTool.mock.calls[0]?.[0]).toMatchObject({
        name: "send_notification",
        arguments: { scope: "biosecurity-agent-alert" },
      });
    } finally {
      database.close();
    }
  });
});
