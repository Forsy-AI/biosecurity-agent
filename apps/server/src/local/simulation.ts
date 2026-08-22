import { nanoid } from "nanoid";
import {
  ClaimSchema,
  SimulationPlanSchema,
  WorldSnapshotSchema,
  type Claim,
  type SimulationPlan,
  type WorldSnapshot,
} from "@biosecurity/contracts";
import { validateSimulationSafety } from "@biosecurity/safety";

export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

export function simulationStepCount(horizon: string): number {
  const match = horizon
    .trim()
    .match(/^(\d+)\s*(h|hour|hours|d|day|days|w|week|weeks|m|month|months)$/i);
  if (!match) return 30;
  const amount = Math.max(1, Number(match[1]));
  const unit = match[2]!.toLowerCase();
  const days = unit.startsWith("h")
    ? Math.max(1, Math.ceil(amount / 24))
    : unit.startsWith("w")
      ? amount * 7
      : unit.startsWith("m")
        ? amount * 30
        : amount;
  return Math.min(365, days);
}

export function createSimulationPlan(input: {
  baseSnapshot: WorldSnapshot;
  horizon: string;
  targetIds?: string[];
  extraContext?: string;
  seed?: number;
}): SimulationPlan {
  validateSimulationSafety(`${input.horizon} ${input.extraContext ?? ""}`);
  const seed = input.seed ?? 7331;
  return SimulationPlanSchema.parse({
    baseSnapshotId: input.baseSnapshot.id,
    horizon: input.horizon,
    seed,
    assumptions: input.extraContext
      ? [{ id: `assumption_${nanoid(8)}`, statement: input.extraContext, source: "user" }]
      : [
          {
            id: `assumption_${nanoid(8)}`,
            statement:
              "Monitoring and reporting conditions remain comparable to the frozen base snapshot.",
            source: "agent",
          },
        ],
    variables: [
      {
        id: "reporting_signal",
        name: "Relative reporting signal",
        initialValue: 1,
        unit: "index",
        uncertainty: 0.35,
      },
      {
        id: "target_exposure",
        name: "Relative target exposure",
        initialValue: 0.2,
        unit: "index",
        uncertainty: 0.45,
      },
    ],
    transitionRules: [
      {
        id: "abstract_signal_drift",
        description: "Advance abstract reporting and exposure indices within bounded uncertainty.",
        expression: "next = clamp(previous + seeded_noise, 0, 2)",
        safetyClass: "abstract-defensive",
      },
    ],
    targetIds: input.targetIds?.length ? input.targetIds : input.baseSnapshot.targetIds,
    safetyClassification: "defensive-forecast",
  });
}

export function runSimulation(
  plan: SimulationPlan,
  baseSnapshot: WorldSnapshot,
  observedClaims: Claim[],
): { plan: SimulationPlan; snapshot: WorldSnapshot; simulatedClaims: Claim[]; diffs: string[] } {
  if (plan.baseSnapshotId !== baseSnapshot.id) throw new Error("Simulation base snapshot mismatch");
  validateSimulationSafety(JSON.stringify(plan));
  const random = seededRandom(plan.seed);
  const steps = simulationStepCount(plan.horizon);
  const snapshotId = `snapshot_sim_${nanoid(10)}`;
  const simulationArtifactId = `simulation:${snapshotId}`;
  const simulatedClaims = plan.targetIds.map((targetId, index) => {
    let reportingSignal = 1;
    let targetExposure = 0.2;
    for (let step = 0; step < steps; step += 1) {
      reportingSignal = Math.max(0, Math.min(2, reportingSignal + (random() - 0.5) * 0.12));
      targetExposure = Math.max(0, Math.min(2, targetExposure + (random() - 0.5) * 0.08));
    }
    const priority =
      reportingSignal + targetExposure > 1.35
        ? "watch more closely"
        : "no material abstract change";
    return ClaimSchema.parse({
      id: `sim_claim_${nanoid(10)}`,
      artifactId: simulationArtifactId,
      subject: { id: targetId, label: `Selected target ${index + 1}`, kind: "target" },
      predicate: "projected-monitoring-priority",
      object: `${priority}; projected reporting index ${reportingSignal.toFixed(2)} and exposure index ${targetExposure.toFixed(2)}`,
      time: { label: plan.horizon },
      confidence: Number((0.42 + random() * 0.28).toFixed(2)),
      state: "simulated",
    });
  });
  const snapshot = WorldSnapshotSchema.parse({
    ...baseSnapshot,
    id: snapshotId,
    asOf: new Date().toISOString(),
    claimIds: [...baseSnapshot.claimIds, ...simulatedClaims.map((claim) => claim.id)],
    materialChanges: simulatedClaims.map((claim) => ({
      id: `change_${claim.id}`,
      summary: `Simulated: ${String(claim.object)}`,
      targetIds: [claim.subject.id],
      claimIds: [claim.id],
      significance: "medium" as const,
    })),
    provenance: {
      ...baseSnapshot.provenance,
      observedClaims: observedClaims.filter((claim) => claim.state === "observed").length,
    },
    simulation: {
      baseSnapshotId: baseSnapshot.id,
      seed: plan.seed,
      horizon: plan.horizon,
      generatedAt: new Date().toISOString(),
    },
  });
  return {
    plan,
    snapshot,
    simulatedClaims,
    diffs: simulatedClaims.map(
      (claim) =>
        `${claim.subject.label}: ${String(claim.object)} (${Math.round(claim.confidence * 100)}% model uncertainty score)`,
    ),
  };
}
