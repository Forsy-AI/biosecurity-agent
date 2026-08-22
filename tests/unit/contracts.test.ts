import { describe, expect, it } from "vitest";
import {
  AgentNotificationSchema,
  ClaimSchema,
  SourceArtifactSchema,
  TargetSchema,
  countsFromEvents,
  type ProcessingEvent,
} from "@biosecurity/contracts";

const now = "2026-08-22T12:00:00.000Z";

describe("contracts", () => {
  it("validates extensible targets", () => {
    const target = TargetSchema.parse({
      id: "t1",
      name: "Cocoa shipment",
      description: "Ghana to Rotterdam",
      inferredKind: "shipment",
      attributes: { lots: 3 },
      locations: [],
      relationships: [],
      contextArtifacts: [],
      customSourceIds: [],
      createdAt: now,
      updatedAt: now,
    });
    expect(target.inferredKind).toBe("shipment");
  });

  it("keeps observed, inferred and simulated claim states explicit", () => {
    for (const state of ["observed", "inferred", "simulated"] as const) {
      expect(
        ClaimSchema.parse({
          id: `claim-${state}`,
          artifactId: "a1",
          subject: { id: "e1", label: "Target", kind: "target" },
          predicate: "state",
          object: "value",
          confidence: 0.5,
          state,
        }).state,
      ).toBe(state);
    }
  });

  it("rejects invalid artifact security state", () => {
    expect(() =>
      SourceArtifactSchema.parse({
        id: "a",
        providerId: "p",
        sourceClass: "news",
        retrievedAt: now,
        contentHash: "1234567890123456",
        rawStorageRef: "raw",
        trustMetadata: {},
        securityState: "trusted",
      }),
    ).toThrow();
  });

  it("derives visible counts from persisted event types and unique languages", () => {
    const base = {
      runId: "r",
      status: "completed",
      createdAt: now,
      metadata: {},
      lane: "TARGET MODELLING",
    };
    const events = [
      { ...base, id: "1", type: "target.modelled", label: "one" },
      { ...base, id: "2", type: "target.modelled", label: "two" },
      { ...base, id: "3", type: "language.detected", label: "EN", metadata: { language: "en" } },
      { ...base, id: "4", type: "language.detected", label: "EN", metadata: { language: "en" } },
    ] as ProcessingEvent[];
    expect(countsFromEvents(events)["targets modelled"]).toBe(2);
    expect(countsFromEvents(events)["languages encountered"]).toBe(1);
  });

  it("requires notification destinations and evidence shape", () => {
    expect(() =>
      AgentNotificationSchema.parse({
        id: "n",
        targetIds: [],
        title: "x",
        summary: "x",
        reason: "x",
        evidenceIds: [],
        worldSnapshotId: "s",
        createdAt: now,
        destinationIds: [],
      }),
    ).toThrow();
  });
});
