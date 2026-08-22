import { nanoid } from "nanoid";
import {
  type Target,
  TargetSchema,
  type TargetModellingResult,
  type TargetRelationship,
} from "@biosecurity/contracts";

const LOCATION_RULES: Array<[RegExp, string, number, number, "locality" | "region" | "country"]> = [
  [/\b(?:hackney|london)\b/i, "London, United Kingdom", 51.5072, -0.1276, "locality"],
  [/\bcornwall\b/i, "Cornwall, United Kingdom", 50.266, -5.0527, "region"],
  [/\bghana\b/i, "Ghana", 7.9465, -1.0232, "country"],
  [/\brotterdam\b/i, "Rotterdam, Netherlands", 51.9244, 4.4777, "locality"],
  [/\bunited kingdom|\buk\b/i, "United Kingdom", 55.3781, -3.436, "country"],
];

const KIND_RULES: Array<[RegExp, string]> = [
  [/\b(dog|cat|horse|cattle|livestock|animal)\b/i, "animal"],
  [/\b(tomato|plant|crop|tree|garden)\b/i, "plant"],
  [/\b(shipment|cargo|container|lot)\b/i, "shipment"],
  [/\b(food|product|ingredient)\b/i, "product"],
  [/\b(school|facility|factory|warehouse|hospital)\b/i, "facility"],
  [/\b(family|household|person|people|students)\b/i, "group"],
];

export type TargetDraft = { id?: string; name: string; description: string };

export function inferTargetKind(text: string): string {
  return KIND_RULES.find(([pattern]) => pattern.test(text))?.[1] ?? "general";
}

export function extractLocations(text: string): Target["locations"] {
  const seen = new Set<string>();
  return LOCATION_RULES.flatMap(([pattern, label, latitude, longitude, resolution]) => {
    if (!pattern.test(text) || seen.has(label)) return [];
    seen.add(label);
    return [{ id: `loc_${nanoid(8)}`, label, latitude, longitude, resolution }];
  });
}

export function modelTargets(
  drafts: TargetDraft[],
  now = new Date().toISOString(),
  agentResult?: TargetModellingResult,
): Target[] {
  const targets = drafts.map((draft, index) => {
    const combined = `${draft.name} ${draft.description}`;
    const enrichment = agentResult?.targets.find((item) => item.index === index);
    const inferredKind = enrichment?.inferredKind ?? inferTargetKind(combined);
    const deterministicLocations = extractLocations(combined);
    const agentLocations =
      enrichment?.locations.map((location) => ({
        id: `loc_${nanoid(8)}`,
        label: location.label,
        ...(location.latitude !== null ? { latitude: location.latitude } : {}),
        ...(location.longitude !== null ? { longitude: location.longitude } : {}),
        resolution: location.resolution,
      })) ?? [];
    return TargetSchema.parse({
      id: draft.id ?? `target_${nanoid(10)}`,
      name: draft.name.trim(),
      description: draft.description.trim(),
      inferredKind,
      attributes: {
        modellingMethod: enrichment ? "codex-enriched" : "deterministic-baseline",
        needsUserReview: inferredKind === "general",
      },
      locations: agentLocations.length ? agentLocations : deterministicLocations,
      relationships: [],
      contextArtifacts: [],
      customSourceIds: [],
      createdAt: now,
      updatedAt: now,
    });
  });

  if (targets.length > 1) {
    for (let index = 0; index < targets.length - 1; index += 1) {
      const from = targets[index];
      const to = targets[index + 1];
      if (!from || !to) continue;
      const sharedLocation = from.locations.some((left) =>
        to.locations.some((right) => left.label === right.label),
      );
      if (sharedLocation) {
        const relationship: TargetRelationship = {
          id: `target_rel_${nanoid(8)}`,
          fromTargetId: from.id,
          toTargetId: to.id,
          type: "co-located",
          label: "Shares a modelled location",
        };
        from.relationships.push(relationship);
      }
    }
  }
  return targets;
}

export type InvestigationQuery = {
  targetId: string;
  language: string;
  query: string;
  sourceClasses: string[];
};

export function buildInvestigationPlan(target: Target): InvestigationQuery[] {
  const location = target.locations[0]?.label;
  const base = [target.name, target.inferredKind, location, "health surveillance alerts recalls"]
    .filter(Boolean)
    .join(" ");
  const queries: InvestigationQuery[] = [
    {
      targetId: target.id,
      language: "en",
      query: base,
      sourceClasses: ["authority", "science", "news", "sensor"],
    },
  ];
  if (/Ghana/i.test(location ?? "")) {
    queries.push({
      targetId: target.id,
      language: "fr",
      query: `${target.name} Ghana surveillance sanitaire rappel`,
      sourceClasses: ["authority", "news"],
    });
  }
  if (/Rotterdam/i.test(location ?? "")) {
    queries.push({
      targetId: target.id,
      language: "nl",
      query: `${target.name} Rotterdam voedselveiligheid waarschuwing`,
      sourceClasses: ["authority", "news"],
    });
  }
  return queries;
}
