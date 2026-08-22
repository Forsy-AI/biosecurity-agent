import { z } from "zod";

export const IdSchema = z.string().min(1).max(160);
export const IsoDateSchema = z.string().datetime();

export const LocationRefSchema = z.object({
  id: IdSchema,
  label: z.string().min(1),
  latitude: z.number().min(-90).max(90).optional(),
  longitude: z.number().min(-180).max(180).optional(),
  resolution: z.enum(["exact", "locality", "region", "country", "unknown"]).default("unknown"),
});

export const EntityRefSchema = z.object({
  id: IdSchema,
  label: z.string().min(1),
  kind: z
    .enum([
      "target",
      "person",
      "group",
      "animal",
      "plant",
      "organism",
      "pathogen",
      "product",
      "ingredient",
      "lot",
      "company",
      "facility",
      "place",
      "event",
      "sensor",
      "observation",
      "document",
    ])
    .or(z.string().min(1)),
});

export const TargetRelationshipSchema = z.object({
  id: IdSchema,
  fromTargetId: IdSchema,
  toTargetId: IdSchema,
  type: z.string().min(1),
  label: z.string().min(1),
});

export const ArtifactRefSchema = z.object({
  id: IdSchema,
  filename: z.string().min(1),
  mediaType: z.string().min(1),
  size: z.number().nonnegative(),
});

export const TargetSchema = z.object({
  id: IdSchema,
  name: z.string().trim().min(1).max(200),
  description: z.string().trim().min(1).max(10_000),
  inferredKind: z.string().optional(),
  attributes: z.record(z.string(), z.unknown()).default({}),
  locations: z.array(LocationRefSchema).default([]),
  relationships: z.array(TargetRelationshipSchema).default([]),
  contextArtifacts: z.array(ArtifactRefSchema).default([]),
  customSourceIds: z.array(IdSchema).default([]),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema,
});

export const SourceClassSchema = z.enum([
  "authority",
  "science",
  "news",
  "social",
  "sensor",
  "custom",
]);

export const SourceArtifactSchema = z.object({
  id: IdSchema,
  providerId: IdSchema,
  sourceClass: SourceClassSchema,
  url: z.string().url().optional(),
  title: z.string().optional(),
  author: z.string().optional(),
  language: z.string().optional(),
  publishedAt: IsoDateSchema.optional(),
  observedAt: IsoDateSchema.optional(),
  retrievedAt: IsoDateSchema,
  contentHash: z.string().min(16),
  rawStorageRef: z.string().min(1),
  licence: z.string().optional(),
  redistribution: z.string().optional(),
  trustMetadata: z.record(z.string(), z.unknown()).default({}),
  securityState: z.enum(["accepted", "quarantined", "rejected"]),
});

export const EvidenceSpanSchema = z.object({
  excerpt: z.string().max(2_000),
  start: z.number().int().nonnegative().optional(),
  end: z.number().int().nonnegative().optional(),
});

export const ClaimSchema = z.object({
  id: IdSchema,
  artifactId: IdSchema,
  subject: EntityRefSchema,
  predicate: z.string().min(1),
  object: EntityRefSchema.or(z.union([z.string(), z.number(), z.boolean()])),
  time: z
    .object({
      start: IsoDateSchema.optional(),
      end: IsoDateSchema.optional(),
      label: z.string().optional(),
    })
    .optional(),
  geography: LocationRefSchema.optional(),
  evidenceSpan: EvidenceSpanSchema.optional(),
  confidence: z.number().min(0).max(1),
  state: z.enum(["observed", "inferred", "simulated"]),
});

export const EntitySchema = EntityRefSchema.extend({
  aliases: z.array(z.string()).default([]),
  attributes: z.record(z.string(), z.unknown()).default({}),
  locations: z.array(LocationRefSchema).default([]),
});

export const MaterialChangeSchema = z.object({
  id: IdSchema,
  summary: z.string().min(1),
  targetIds: z.array(IdSchema),
  claimIds: z.array(IdSchema),
  significance: z.enum(["low", "medium", "high"]),
});

export const ProtectionSchema = z.object({
  id: IdSchema,
  targetIds: z.array(IdSchema).min(1),
  title: z.string().min(1),
  summary: z.string().min(1),
  rationale: z.string().min(1),
  urgency: z.enum(["informational", "time-sensitive", "urgent"]),
  evidenceIds: z.array(IdSchema),
  uncertainty: z.string().min(1),
  professionalEscalation: z.string().optional(),
  toolProposal: z
    .object({
      id: IdSchema,
      tool: z.string().min(1),
      arguments: z.record(z.string(), z.unknown()),
      expectedEffect: z.string().min(1),
      riskLevel: z.enum(["low", "medium", "high"]),
      evidenceIds: z.array(IdSchema),
      reversible: z.boolean(),
      approvalRequired: z.boolean(),
    })
    .optional(),
  status: z.enum(["suggested", "approval-required", "approved", "executed", "failed", "dismissed"]),
});

export const CoverageSummarySchema = z.object({
  searchedClasses: z.array(SourceClassSchema),
  unavailableProviders: z.array(z.string()),
  languages: z.array(z.string()),
  limitations: z.array(z.string()),
});

export const WorldSnapshotSchema = z.object({
  id: IdSchema,
  worldId: IdSchema,
  asOf: IsoDateSchema,
  targetIds: z.array(IdSchema),
  entityIds: z.array(IdSchema),
  claimIds: z.array(IdSchema),
  materialChanges: z.array(MaterialChangeSchema),
  protectionIds: z.array(IdSchema),
  coverage: CoverageSummarySchema,
  provenance: z.object({
    artifactIds: z.array(IdSchema),
    observedClaims: z.number().int().nonnegative(),
  }),
  simulation: z
    .object({
      baseSnapshotId: IdSchema,
      seed: z.number().int(),
      horizon: z.string(),
      generatedAt: IsoDateSchema,
    })
    .optional(),
});

export const LaneSchema = z.enum([
  "TARGET MODELLING",
  "OFFICIAL & SCIENTIFIC",
  "NEWS & OPEN WEB",
  "SOCIAL & COMMUNITY",
  "SENSORS & SURVEILLANCE",
  "CUSTOM SOURCES",
  "WORLD SYNTHESIS",
  "LIVE WATCH",
]);

export const ProcessingEventSchema = z.object({
  id: IdSchema,
  runId: IdSchema,
  lane: LaneSchema,
  type: z.string().min(1),
  status: z.enum(["started", "progress", "completed", "failed"]),
  label: z.string().min(1),
  entityId: IdSchema.optional(),
  artifactId: IdSchema.optional(),
  countDelta: z.number().int().optional(),
  createdAt: IsoDateSchema,
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export const WatcherSchema = z.object({
  id: IdSchema,
  runId: IdSchema,
  targetIds: z.array(IdSchema),
  query: z.string().min(1),
  sourceProviders: z.array(IdSchema),
  cadence: z.number().int().positive(),
  language: z.string(),
  geography: z.string(),
  cursor: z.string().nullable(),
  lastSuccessfulRun: IsoDateSchema.nullable(),
  lastMaterialUpdate: IsoDateSchema.nullable(),
  health: z.enum(["starting", "healthy", "degraded", "paused"]),
});

export const SimulationPlanSchema = z.object({
  baseSnapshotId: IdSchema,
  horizon: z.string().min(1).max(100),
  seed: z.number().int(),
  assumptions: z.array(
    z.object({ id: IdSchema, statement: z.string().min(1), source: z.enum(["user", "agent"]) }),
  ),
  variables: z.array(
    z.object({
      id: IdSchema,
      name: z.string(),
      initialValue: z.number(),
      unit: z.string(),
      uncertainty: z.number().min(0).max(1),
    }),
  ),
  transitionRules: z.array(
    z.object({
      id: IdSchema,
      description: z.string(),
      expression: z.string(),
      safetyClass: z.literal("abstract-defensive"),
    }),
  ),
  targetIds: z.array(IdSchema).min(1),
  safetyClassification: z.literal("defensive-forecast"),
});

export const AgentProviderSchema = z.enum([
  "mock",
  "codex",
  "anthropic",
  "openai-compatible",
  "ollama",
  "generic-http",
]);
export const AgentConfigSchema = z.object({
  provider: AgentProviderSchema,
  model: z.string().min(1).max(200),
  endpoint: z.string().url().optional(),
  apiKey: z.string().max(10_000).optional(),
  instructions: z.string().max(30_000).default(""),
  parameters: z
    .object({
      temperature: z.number().min(0).max(2).optional(),
      maxTokens: z.number().int().positive().max(100_000).optional(),
    })
    .catchall(z.unknown())
    .default({}),
});

export const TargetKindSchema = z.enum([
  "person",
  "group",
  "animal",
  "plant",
  "shipment",
  "product",
  "facility",
  "place",
  "organisation",
  "supply-chain",
  "surveillance-system",
  "event",
  "general",
]);

export const TargetModellingResultSchema = z.object({
  summary: z.string().min(1).max(2_000),
  targets: z.array(
    z.object({
      index: z.number().int().nonnegative(),
      inferredKind: TargetKindSchema,
      locations: z.array(
        z.object({
          label: z.string().min(1).max(200),
          latitude: z.number().min(-90).max(90).nullable(),
          longitude: z.number().min(-180).max(180).nullable(),
          resolution: z.enum(["exact", "locality", "region", "country", "unknown"]),
        }),
      ),
    }),
  ),
});

export const CustomSourceKindSchema = z.enum([
  "url",
  "domain",
  "search",
  "rss",
  "sitemap",
  "rest",
  "graphql",
  "webhook",
  "mcp",
  "local-folder",
  "social",
  "authenticated-platform",
]);

export const CustomSourceSchema = z.object({
  id: IdSchema,
  kind: CustomSourceKindSchema,
  label: z.string().min(1).max(200),
  value: z.string().min(1).max(10_000),
  targetIds: z.array(IdSchema),
  mapping: z.record(z.string(), z.string()).optional(),
  enabled: z.boolean().default(true),
});

export const SourceManifestSchema = z.object({
  id: IdSchema,
  name: z.string().min(1),
  sourceClass: SourceClassSchema,
  geographicCoverage: z.array(z.string()),
  languages: z.array(z.string()),
  dataEventTypes: z.array(z.string()),
  accessMethod: z.string(),
  authenticationRequirements: z.string(),
  cadence: z.string(),
  typicalDelay: z.string(),
  licence: z.string(),
  redistributionPermission: z.string(),
  commercialUseStatus: z.string(),
  knownLimitations: z.array(z.string()),
  health: z.enum(["available", "feature-flagged", "unconfigured", "unavailable"]),
});

export const StartRunRequestSchema = z.object({
  agent: AgentConfigSchema,
  targets: z
    .array(
      z.object({
        id: IdSchema.optional(),
        name: z.string().min(1),
        description: z.string().min(1),
      }),
    )
    .min(1),
  customSources: z.array(CustomSourceSchema).default([]),
  notificationsEnabled: z.boolean().default(false),
  notificationDestinations: z.array(z.lazy(() => NotificationDestinationInputSchema)).default([]),
  demo: z.boolean().default(false),
});

export const NotificationDestinationSchema = z.object({
  id: IdSchema,
  runId: IdSchema,
  type: z.enum(["smtp", "webhook", "mcp", "mock"]),
  name: z.string().min(1).max(200),
  destination: z.string().min(1).max(500),
  targetIds: z.array(IdSchema),
  enabled: z.boolean(),
  allowPrivateNetwork: z.boolean().default(false),
  includeSensitive: z.boolean().default(false),
  simulationNotifications: z.boolean().default(false),
  settings: z.record(z.string(), z.unknown()).default({}),
  createdAt: IsoDateSchema,
  updatedAt: IsoDateSchema,
});

export const NotificationDestinationInputSchema = z.object({
  type: z.enum(["smtp", "webhook", "mcp", "mock"]),
  name: z.string().min(1).max(200),
  destination: z.string().min(1).max(500),
  targetIds: z.array(IdSchema).default([]),
  enabled: z.boolean().default(true),
  allowPrivateNetwork: z.boolean().default(false),
  includeSensitive: z.boolean().default(false),
  simulationNotifications: z.boolean().default(false),
  smtp: z
    .object({
      host: z.string().min(1),
      port: z.number().int().min(1).max(65_535),
      username: z.string().optional(),
      password: z.string().optional(),
      from: z.string().email(),
      secure: z.boolean().default(false),
      requireTls: z.boolean().default(true),
    })
    .optional(),
  webhookUrl: z.string().optional(),
  mcp: z
    .object({
      serverUrl: z.string().url(),
      toolName: z.string().min(1).max(200),
      bearerToken: z.string().optional(),
    })
    .optional(),
});

export const AgentNotificationSchema = z.object({
  id: IdSchema,
  targetIds: z.array(IdSchema).min(1),
  title: z.string().min(1).max(200),
  summary: z.string().min(1).max(2_000),
  reason: z.string().min(1).max(2_000),
  evidenceIds: z.array(IdSchema),
  worldSnapshotId: IdSchema,
  createdAt: IsoDateSchema,
  destinationIds: z.array(IdSchema).min(1),
});

export const NotificationDeliverySchema = z.object({
  id: IdSchema,
  notificationId: IdSchema,
  destinationId: IdSchema,
  status: z.enum(["sent", "failed", "skipped"]),
  attemptedAt: IsoDateSchema,
  errorCode: z.string().optional(),
  errorMessage: z.string().optional(),
});

export const EvidenceRecordSchema = z.object({
  id: IdSchema,
  sourceTitle: z.string(),
  sourceUrl: z.string().url().optional(),
  sourceClass: SourceClassSchema,
  excerpt: z.string(),
  publishedAt: IsoDateSchema.optional(),
  retrievedAt: IsoDateSchema,
  geographicResolution: z.string(),
  language: z.string(),
  claim: z.string(),
  supportingEvidenceIds: z.array(IdSchema),
  contradictingEvidenceIds: z.array(IdSchema),
  targetIds: z.array(IdSchema).default([]),
  targetRelevance: z.string(),
  material: z.boolean().default(false),
  confidence: z.number().min(0).max(1),
  status: z.enum(["observed", "inferred", "simulated"]),
  licenceNotes: z.string(),
});

export const WorldViewSchema = z.object({
  runId: IdSchema,
  phase: z.enum(["building", "live", "failed"]),
  demo: z.boolean(),
  demoDisclosure: z.string().optional(),
  targets: z.array(TargetSchema),
  artifacts: z.array(SourceArtifactSchema),
  claims: z.array(ClaimSchema),
  entities: z.array(EntitySchema),
  snapshots: z.array(WorldSnapshotSchema),
  protections: z.array(ProtectionSchema),
  evidence: z.array(EvidenceRecordSchema),
  watchers: z.array(WatcherSchema),
  events: z.array(ProcessingEventSchema),
  counts: z.record(z.string(), z.number().int().nonnegative()),
});

export type Target = z.infer<typeof TargetSchema>;
export type ArtifactRef = z.infer<typeof ArtifactRefSchema>;
export type SourceArtifact = z.infer<typeof SourceArtifactSchema>;
export type Claim = z.infer<typeof ClaimSchema>;
export type Entity = z.infer<typeof EntitySchema>;
export type WorldSnapshot = z.infer<typeof WorldSnapshotSchema>;
export type ProcessingEvent = z.infer<typeof ProcessingEventSchema>;
export type Watcher = z.infer<typeof WatcherSchema>;
export type SimulationPlan = z.infer<typeof SimulationPlanSchema>;
export type Protection = z.infer<typeof ProtectionSchema>;
export type AgentConfig = z.infer<typeof AgentConfigSchema>;
export type TargetModellingResult = z.infer<typeof TargetModellingResultSchema>;
export type CustomSource = z.infer<typeof CustomSourceSchema>;
export type SourceManifest = z.infer<typeof SourceManifestSchema>;
export type EvidenceRecord = z.infer<typeof EvidenceRecordSchema>;
export type WorldView = z.infer<typeof WorldViewSchema>;
export type Lane = z.infer<typeof LaneSchema>;
export type TargetRelationship = z.infer<typeof TargetRelationshipSchema>;
export type NotificationDestination = z.infer<typeof NotificationDestinationSchema>;
export type NotificationDestinationInput = z.input<typeof NotificationDestinationInputSchema>;
export type AgentNotification = z.infer<typeof AgentNotificationSchema>;
export type NotificationDelivery = z.infer<typeof NotificationDeliverySchema>;

export const COUNTABLE_EVENT_TYPES: Record<string, string> = {
  "target.modelled": "targets modelled",
  "query.created": "queries generated",
  "source.searched": "sources searched",
  "artifact.retrieved": "artifacts retrieved",
  "language.detected": "languages encountered",
  "claim.extracted": "claims extracted",
  "duplicate.merged": "duplicate clusters",
  "entity.resolved": "entities resolved",
  "relationship.created": "relationships created",
  "target.linked": "target intersections",
  "watcher.created": "watchers active",
};

export function countsFromEvents(events: ProcessingEvent[]): Record<string, number> {
  const counts: Record<string, number> = Object.fromEntries(
    Object.values(COUNTABLE_EVENT_TYPES).map((key) => [key, 0]),
  );
  const languages = new Set<string>();
  for (const event of events) {
    const key = COUNTABLE_EVENT_TYPES[event.type];
    if (!key || event.status === "failed") continue;
    if (event.type === "language.detected") {
      const language =
        typeof event.metadata.language === "string" ? event.metadata.language : event.label;
      languages.add(language);
      counts[key] = languages.size;
    } else {
      counts[key] = (counts[key] ?? 0) + (event.countDelta ?? 1);
    }
  }
  return counts;
}
