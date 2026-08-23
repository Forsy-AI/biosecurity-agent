import { describe, expect, it } from "vitest";
import { parseNaturalCommand } from "../../apps/cli/src/terminal.js";

describe("terminal agent command interpretation", () => {
  it.each([
    ["protect my dog Milo in London", "add-target"],
    ["Milo is travelling to Cornwall Saturday through Monday", "update-target"],
    ["watch https://example.com/feed.xml for Milo", "add-source"],
    ["add ~/Downloads/context.pdf to Milo", "add-context"],
    ["simulate the next 30 days", "simulate"],
    ["explain the most relevant update", "changes"],
    ["show evidence", "evidence"],
    ["configure notifications", "notifications"],
    ["open world", "open-world"],
  ])("maps %s to %s", (input, type) => {
    expect(parseNaturalCommand(input).type).toBe(type);
  });

  it("keeps simulation parameters bounded and structured", () => {
    expect(parseNaturalCommand("simulate the next 6 weeks")).toMatchObject({
      type: "simulate",
      horizon: "6w",
    });
    expect(parseNaturalCommand("simulate the next 24 hours")).toMatchObject({
      type: "simulate",
      horizon: "24h",
    });
  });
});
