import { nanoid } from "nanoid";
import {
  ProtectionSchema,
  type Claim,
  type EvidenceRecord,
  type Protection,
  type Target,
} from "@biosecurity/contracts";
import type { BiosecurityDatabase } from "./state.js";

export function suggestProtection(
  targets: Target[],
  claims: Claim[],
  evidence: EvidenceRecord[],
  options: { demo?: boolean } = {},
): Protection {
  const relevantEvidence = evidence
    .filter((item) => item.status === "observed" && item.material)
    .sort((left, right) => right.retrievedAt.localeCompare(left.retrievedAt))
    .slice(0, 3);
  if (relevantEvidence.length === 0)
    throw new Error("Protection suggestions require observed evidence");
  const relevantTargetIds = new Set(relevantEvidence.flatMap((item) => item.targetIds));
  const relevantTargets = targets.filter((target) => relevantTargetIds.has(target.id));
  const protectionTargets = relevantTargets.length ? relevantTargets : targets.slice(0, 1);
  const plantTarget = protectionTargets.find((target) => target.inferredKind === "plant");
  const targetIds = protectionTargets.map((target) => target.id);
  return ProtectionSchema.parse({
    id: `protection_${nanoid(10)}`,
    targetIds,
    title: plantTarget
      ? "Verify the plant signal before changing controls"
      : "Confirm the signal against current official guidance",
    summary: plantTarget
      ? options.demo
        ? "Photograph affected leaves, compare new observations over time, and use an official plant-health identification route before acting."
        : "Review the cited plant-related records, confirm current applicability with an official plant-health source, and collect direct observations before changing controls."
      : "Keep monitoring, confirm relevance and timing, and consult the current official source or a qualified professional if conditions change.",
    rationale: options.demo
      ? `The world contains ${claims.filter((claim) => claim.state === "observed").length} observed fixture claims, but source independence and target exposure remain uncertain.`
      : `The world contains ${claims.filter((claim) => claim.state === "observed").length} observed source-derived claims. Retrieval provenance and lexical relevance do not establish exposure, causation, or diagnosis.`,
    urgency: "informational",
    evidenceIds: relevantEvidence.map((item) => item.id),
    uncertainty: options.demo
      ? "The demo evidence is fictional and frozen; this suggestion is a workflow example, not medical, veterinary, or plant-health diagnosis."
      : "Source freshness, independence, geographic precision, and target exposure remain uncertain; this is a defensive workflow suggestion, not a medical, veterinary, or plant-health diagnosis.",
    professionalEscalation:
      "Use an appropriate official or qualified local professional when identification or target health materially changes.",
    toolProposal: {
      id: `tool_${nanoid(10)}`,
      tool: "local.mock-reminder",
      arguments: { targetId: targetIds[0], message: "Review new observations in 48 hours" },
      expectedEffect: "Write a harmless reminder to the local run audit log.",
      riskLevel: "low",
      evidenceIds: relevantEvidence.map((item) => item.id),
      reversible: true,
      approvalRequired: true,
    },
    status: "approval-required",
  });
}

export type ToolDecision = { protection: Protection; executed: boolean; auditMessage: string };

export function decideToolProposal(
  database: BiosecurityDatabase,
  runId: string,
  protectionId: string,
  decision: "approve" | "reject",
): ToolDecision {
  const protection = database.listProtections(runId).find((entry) => entry.id === protectionId);
  if (!protection?.toolProposal) throw new Error("Tool proposal not found");
  if (decision === "reject") {
    const dismissed = database.updateProtectionStatus(runId, protectionId, "dismissed");
    database.updateToolProposal(protection.toolProposal.id, "rejected");
    return {
      protection: dismissed,
      executed: false,
      auditMessage: "Proposal rejected; no action executed.",
    };
  }
  if (protection.toolProposal.tool !== "local.mock-reminder")
    throw new Error("Tool is not registered");
  if (!protection.toolProposal.approvalRequired) throw new Error("Unexpected approval policy");
  const executed = database.updateProtectionStatus(runId, protectionId, "executed");
  database.updateToolProposal(protection.toolProposal.id, "executed");
  return {
    protection: executed,
    executed: true,
    auditMessage: `Approved harmless local reminder: ${String(protection.toolProposal.arguments.message)}`,
  };
}
