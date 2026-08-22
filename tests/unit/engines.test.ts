import { describe, expect, it } from "vitest";
import {
  buildInvestigationPlan,
  inferTargetKind,
  modelTargets,
} from "../../apps/server/src/local/targeting.js";
import {
  createSimulationPlan,
  runSimulation,
  simulationStepCount,
} from "../../apps/server/src/local/simulation.js";
import { suggestProtection } from "../../apps/server/src/local/protection.js";
import { normalizeExternalPublishedAt } from "../../apps/server/src/local/public-sources.js";
import {
  deduplicateArtifacts,
  detectContradictions,
  estimateCorroboration,
  isMaterialTargetContent,
  normalizedEntityKey,
  publicSourceQuery,
  targetRelevance,
} from "../../apps/server/src/local/world.js";
import type { Claim, SourceArtifact, WorldSnapshot } from "@biosecurity/contracts";

const now = "2026-08-22T12:00:00.000Z";

describe("target and world engines", () => {
  it("normalises valid provider timestamps and drops malformed external dates", () => {
    expect(normalizeExternalPublishedAt("2026-08-22T12:00:00Z")).toBe(now);
    expect(normalizeExternalPublishedAt("not-a-provider-date")).toBeUndefined();
    expect(normalizeExternalPublishedAt("+100000-01-01T00:00:00Z")).toBeUndefined();
  });

  it("infers broad kinds without asking the user for a type", () => {
    expect(inferTargetKind("six tomato plants in Hackney")).toBe("plant");
    expect(inferTargetKind("a cocoa shipment from Ghana")).toBe("shipment");
  });

  it("models locations and multilingual investigation variants", () => {
    const [target] = modelTargets(
      [{ name: "Cocoa shipment", description: "Ghana to Rotterdam" }],
      now,
    );
    expect(target?.locations.map((location) => location.label)).toEqual([
      "Ghana",
      "Rotterdam, Netherlands",
    ]);
    expect(buildInvestigationPlan(target!).map((query) => query.language)).toEqual(["en", "fr"]);
    const publicQuery = publicSourceQuery(target!);
    expect(publicQuery).toContain("shipment");
    expect(publicQuery).toContain("Ghana");
    expect(publicQuery).not.toContain("Cocoa shipment");
  });

  it("retains validated Codex target enrichment without changing user-authored target text", () => {
    const [target] = modelTargets(
      [{ name: "Public school estate", description: "Public schools across New York City" }],
      now,
      {
        summary: "A public facility target in a named city.",
        targets: [
          {
            index: 0,
            inferredKind: "facility",
            locations: [
              {
                label: "New York City, United States",
                latitude: 40.7128,
                longitude: -74.006,
                resolution: "locality",
              },
            ],
          },
        ],
      },
    );
    expect(target).toMatchObject({
      name: "Public school estate",
      description: "Public schools across New York City",
      inferredKind: "facility",
      attributes: { modellingMethod: "codex-enriched" },
      locations: [{ label: "New York City, United States", latitude: 40.7128 }],
    });
  });

  it("normalises aliases and clusters exact content hashes", () => {
    expect(normalizedEntityKey("  Milo’s-Dog ")).toBe("milo s dog");
    const artifact = (id: string, providerId: string): SourceArtifact => ({
      id,
      providerId,
      sourceClass: "news",
      retrievedAt: now,
      contentHash: "1234567890123456",
      rawStorageRef: id,
      trustMetadata: {},
      securityState: "accepted",
    });
    expect(
      deduplicateArtifacts([artifact("a", "one"), artifact("b", "two")])[0]?.duplicates,
    ).toHaveLength(1);
  });

  it("detects claim contradictions and independent corroboration", () => {
    const claim = (id: string, artifactId: string, object: string): Claim => ({
      id,
      artifactId,
      subject: { id: "e", label: "Product lot", kind: "product" },
      predicate: "recall-state",
      object,
      confidence: 0.5,
      state: "observed",
    });
    const artifacts = ["one", "two"].map((providerId, index) => ({
      id: `a${index}`,
      providerId,
      sourceClass: "authority" as const,
      retrievedAt: now,
      contentHash: `${index}`.padEnd(16, "0"),
      rawStorageRef: `${index}`,
      trustMetadata: {},
      securityState: "accepted" as const,
    }));
    expect(
      estimateCorroboration(
        claim("c1", "a0", "active"),
        [claim("c1", "a0", "active"), claim("c2", "a1", "active")],
        artifacts,
      ),
    ).toBeGreaterThan(0.5);
    expect(
      detectContradictions([claim("c1", "a0", "active"), claim("c2", "a1", "closed")]),
    ).toHaveLength(1);
  });

  it("scores target relevance from target and geographic overlap", () => {
    const [target] = modelTargets([{ name: "Tomato plants", description: "Hackney London" }], now);
    const claim: Claim = {
      id: "c",
      artifactId: "a",
      subject: { id: "e", label: "Hackney tomato plants", kind: "plant" },
      predicate: "monitoring",
      object: "new signal",
      confidence: 0.5,
      state: "observed",
    };
    expect(targetRelevance(target!, claim)).toBeGreaterThan(0.3);
    const protection = suggestProtection(
      [target!],
      [claim],
      [
        {
          id: "evidence-live",
          sourceTitle: "Official plant notice",
          sourceClass: "authority",
          excerpt: "A current public plant notice.",
          retrievedAt: now,
          geographicResolution: "city",
          language: "en",
          claim: "The notice was retrieved for review.",
          supportingEvidenceIds: [],
          contradictingEvidenceIds: [],
          targetIds: [target!.id],
          targetRelevance: "Matched the plant target.",
          material: true,
          confidence: 0.7,
          status: "observed",
          licenceNotes: "Open Government Licence",
        },
      ],
    );
    expect(protection.uncertainty).not.toContain("fictional and frozen");
    expect(protection.rationale).toContain("source-derived claims");
  });

  it("scopes a protection to the target named by its material evidence", () => {
    const [unrelated, affected] = modelTargets(
      [
        { id: "target-ship", name: "Public cruise ship", description: "Travel monitoring" },
        { id: "target-food", name: "PrepWorld food recall", description: "Product recall" },
      ],
      now,
    );
    const protection = suggestProtection(
      [unrelated!, affected!],
      [],
      [
        {
          id: "evidence-food",
          sourceTitle: "Official food recall",
          sourceClass: "authority",
          excerpt: "A public product recall notice.",
          retrievedAt: now,
          geographicResolution: "country",
          language: "en",
          claim: "The recall notice was retrieved and isolated.",
          supportingEvidenceIds: [],
          contradictingEvidenceIds: [],
          targetIds: [affected!.id],
          targetRelevance: "Explicitly scoped to the food product.",
          material: true,
          confidence: 0.8,
          status: "observed",
          licenceNotes: "Source terms apply",
        },
      ],
    );
    expect(protection.targetIds).toEqual([affected!.id]);
    expect(protection.toolProposal?.arguments.targetId).toBe(affected!.id);
  });

  it("does not turn generic retrieved pages into target intersections", () => {
    const [target] = modelTargets(
      [{ name: "Kent tomato crop", description: "Tomato plants grown in Kent" }],
      now,
    );
    expect(
      isMaterialTargetContent(target!, "General international disease outbreak index", {
        retrievalMode: "document",
      }),
    ).toBe(false);
    expect(
      isMaterialTargetContent(target!, "Kent tomato crop pest surveillance update", {
        retrievalMode: "discovery-metadata",
      }),
    ).toBe(true);
    expect(
      isMaterialTargetContent(
        modelTargets(
          [
            {
              name: "United Kingdom public garden sector",
              description:
                "The garden and environmental horticulture sector across the United Kingdom",
            },
          ],
          now,
        )[0]!,
        "Unrelated medicine report from the United Kingdom",
        { retrievalMode: "discovery-metadata" },
      ),
    ).toBe(false);
    expect(
      isMaterialTargetContent(
        modelTargets(
          [
            {
              name: "Synthetic Kent community tomato garden",
              description: "A synthetic community tomato garden in Kent using public plant records",
            },
          ],
          now,
        )[0]!,
        "An untargeted wastewater observation for a different community",
        { retrievalMode: "discovery-metadata" },
      ),
    ).toBe(false);
    expect(
      isMaterialTargetContent(target!, "A tomato notice", {
        explicitlyTargeted: true,
        retrievalMode: "document",
      }),
    ).toBe(true);
  });
});

describe("simulation", () => {
  const snapshot: WorldSnapshot = {
    id: "base",
    worldId: "world",
    asOf: now,
    targetIds: ["t1"],
    entityIds: [],
    claimIds: [],
    materialChanges: [],
    protectionIds: [],
    coverage: { searchedClasses: [], unavailableProviders: [], languages: [], limitations: [] },
    provenance: { artifactIds: [], observedClaims: 0 },
  };

  it("is reproducible with an explicit seed and preserves base claim IDs", () => {
    const plan = createSimulationPlan({ baseSnapshot: snapshot, horizon: "14 days", seed: 42 });
    const one = runSimulation(plan, snapshot, []);
    const two = runSimulation(plan, snapshot, []);
    expect(one.simulatedClaims.map((claim) => [claim.object, claim.confidence])).toEqual(
      two.simulatedClaims.map((claim) => [claim.object, claim.confidence]),
    );
    expect(one.snapshot.claimIds.slice(0, snapshot.claimIds.length)).toEqual(snapshot.claimIds);
    expect(one.simulatedClaims.every((claim) => claim.state === "simulated")).toBe(true);
  });

  it("advances longer horizons through more bounded abstract steps", () => {
    expect(simulationStepCount("24h")).toBe(1);
    expect(simulationStepCount("7d")).toBe(7);
    const short = runSimulation(
      createSimulationPlan({ baseSnapshot: snapshot, horizon: "24h", seed: 7331 }),
      snapshot,
      [],
    );
    const longer = runSimulation(
      createSimulationPlan({ baseSnapshot: snapshot, horizon: "7d", seed: 7331 }),
      snapshot,
      [],
    );
    expect(short.simulatedClaims[0]?.object).not.toEqual(longer.simulatedClaims[0]?.object);
  });
});
