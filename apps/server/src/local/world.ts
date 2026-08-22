import { nanoid } from "nanoid";
import {
  ClaimSchema,
  EntitySchema,
  EvidenceRecordSchema,
  ProcessingEventSchema,
  SourceArtifactSchema,
  TargetModellingResultSchema,
  WorldSnapshotSchema,
  type Claim,
  type CustomSource,
  type Entity,
  type EvidenceRecord,
  type Lane,
  type ProcessingEvent,
  type SourceArtifact,
  type Target,
  type Watcher,
  type WorldSnapshot,
} from "@biosecurity/contracts";
import type { BiosecurityDatabase } from "./state.js";
import { isolateHtml, isolateText, type IsolatedContent } from "@biosecurity/safety";
import {
  BlueskyPublicDiscoveryProvider,
  DirectHttpRetrievalProvider,
  GdeltDiscoveryProvider,
  normalizeExternalPublishedAt,
  RssAtomDiscoveryProvider,
  SafeHttpClient,
  XmlSitemapDiscoveryProvider,
} from "./public-sources.js";
import { buildInvestigationPlan, modelTargets, type TargetDraft } from "./targeting.js";

export function normalizedEntityKey(label: string): string {
  return label
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

export function resolveEntity(
  entities: Entity[],
  candidate: Entity,
): { entity: Entity; merged: boolean } {
  const key = normalizedEntityKey(candidate.label);
  const match = entities.find(
    (entity) =>
      normalizedEntityKey(entity.label) === key ||
      entity.aliases.some((alias) => normalizedEntityKey(alias) === key),
  );
  if (!match) return { entity: candidate, merged: false };
  const aliases = new Set([...match.aliases, candidate.label, ...candidate.aliases]);
  return { entity: EntitySchema.parse({ ...match, aliases: [...aliases] }), merged: true };
}

export function deduplicateArtifacts(
  artifacts: SourceArtifact[],
): Array<{ primary: SourceArtifact; duplicates: SourceArtifact[] }> {
  const clusters = new Map<string, SourceArtifact[]>();
  for (const artifact of artifacts) {
    const values = clusters.get(artifact.contentHash) ?? [];
    values.push(artifact);
    clusters.set(artifact.contentHash, values);
  }
  return [...clusters.values()].map(([primary, ...duplicates]) => ({
    primary: primary!,
    duplicates,
  }));
}

export function estimateCorroboration(
  claim: Claim,
  claims: Claim[],
  artifacts: SourceArtifact[],
): number {
  const artifact = artifacts.find((item) => item.id === claim.artifactId);
  const key = `${normalizedEntityKey(claim.subject.label)}|${claim.predicate}|${JSON.stringify(claim.object)}`;
  const independentProviders = new Set(
    claims
      .filter(
        (candidate) =>
          `${normalizedEntityKey(candidate.subject.label)}|${candidate.predicate}|${JSON.stringify(candidate.object)}` ===
          key,
      )
      .map((candidate) => artifacts.find((item) => item.id === candidate.artifactId)?.providerId)
      .filter(Boolean),
  );
  if (artifact) independentProviders.add(artifact.providerId);
  return Math.min(1, claim.confidence + Math.max(0, independentProviders.size - 1) * 0.12);
}

export function detectContradictions(
  claims: Claim[],
): Array<{ left: string; right: string; reason: string }> {
  const contradictions: Array<{ left: string; right: string; reason: string }> = [];
  for (let leftIndex = 0; leftIndex < claims.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < claims.length; rightIndex += 1) {
      const left = claims[leftIndex];
      const right = claims[rightIndex];
      if (!left || !right) continue;
      if (
        normalizedEntityKey(left.subject.label) !== normalizedEntityKey(right.subject.label) ||
        left.predicate !== right.predicate
      )
        continue;
      if (JSON.stringify(left.object) !== JSON.stringify(right.object)) {
        contradictions.push({
          left: left.id,
          right: right.id,
          reason: "Same subject and predicate have different reported objects",
        });
      }
    }
  }
  return contradictions;
}

export function targetRelevance(target: Target, claim: Claim): number {
  const haystack =
    `${claim.subject.label} ${claim.predicate} ${JSON.stringify(claim.object)} ${claim.geography?.label ?? ""}`.toLowerCase();
  const terms =
    `${target.name} ${target.description} ${target.inferredKind ?? ""} ${target.locations.map((item) => item.label).join(" ")}`
      .toLowerCase()
      .split(/\W+/)
      .filter((term) => term.length > 3);
  const overlap = new Set(terms.filter((term) => haystack.includes(term))).size;
  return Math.min(1, 0.18 + overlap * 0.16);
}

export function isMaterialChange(
  previous: WorldSnapshot | undefined,
  next: WorldSnapshot,
): boolean {
  if (!previous) return true;
  return (
    next.claimIds.some((id) => !previous.claimIds.includes(id)) ||
    next.protectionIds.some((id) => !previous.protectionIds.includes(id)) ||
    next.materialChanges.some((change) => change.significance !== "low")
  );
}

type DemoFact = {
  providerId: string;
  sourceClass: SourceArtifact["sourceClass"];
  title: string;
  filename: string;
  language: string;
  text: string;
  subject: { label: string; kind: string };
  predicate: string;
  object: string;
  targetIndex: number;
  confidence: number;
  longitude: number;
  latitude: number;
  locationLabel: string;
  licence: string;
};

export const DEMO_FACTS: DemoFact[] = [
  {
    providerId: "demo-official",
    sourceClass: "authority",
    title: "Frozen scenario · international outbreak coordination bulletin",
    filename: "international-coordination.txt",
    language: "en",
    text: "Fictional high-level fixture: an international coordination bulletin records an unexplained febrile-event signal in Central Africa and requests enhanced reporting. No biological mechanism or diagnosis is asserted.",
    subject: { label: "Central Africa event signal", kind: "event" },
    predicate: "international-monitoring-signal",
    object: "enhanced cross-border reporting requested in frozen scenario",
    targetIndex: 2,
    confidence: 0.82,
    longitude: 15.2663,
    latitude: -4.4419,
    locationLabel: "Kinshasa, Democratic Republic of the Congo",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-science",
    sourceClass: "science",
    title: "Frozen scenario · multi-region epidemiology evidence review",
    filename: "epidemiology-review.txt",
    language: "en",
    text: "Fictional high-level fixture: a rapid evidence review describes uncertain travel-associated clustering across several reporting regions while explicitly withholding causal conclusions.",
    subject: { label: "International evidence review", kind: "science" },
    predicate: "travel-association-context",
    object: "multi-region reporting pattern remains under review",
    targetIndex: 2,
    confidence: 0.74,
    longitude: 6.1432,
    latitude: 46.2044,
    locationLabel: "Geneva, Switzerland",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-official",
    sourceClass: "authority",
    title: "Frozen scenario · UK port-health enhanced monitoring notice",
    filename: "heathrow-port-health.txt",
    language: "en",
    text: "Fictional high-level fixture: UK port-health teams increase non-invasive arrival monitoring for selected international routes while routine travel continues.",
    subject: { label: "Heathrow arrival surveillance", kind: "surveillance-system" },
    predicate: "arrival-monitoring-status",
    object: "enhanced non-invasive monitoring active in frozen scenario",
    targetIndex: 2,
    confidence: 0.9,
    longitude: -0.4543,
    latitude: 51.47,
    locationLabel: "London Heathrow, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-science",
    sourceClass: "science",
    title: "Frozen scenario · companion-animal interface review",
    filename: "companion-animal-review.txt",
    language: "en",
    text: "Fictional high-level fixture: veterinary surveillance reviewers find no confirmed companion-animal disease signal but recommend tracking household and travel context separately.",
    subject: { label: "London companion-animal network", kind: "animal" },
    predicate: "host-surveillance-context",
    object: "no confirmed animal signal; contextual monitoring continues",
    targetIndex: 1,
    confidence: 0.77,
    longitude: -0.1276,
    latitude: 51.5072,
    locationLabel: "London, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-official",
    sourceClass: "authority",
    title: "Frozen scenario · Singapore travel-health update",
    filename: "singapore-travel-health.txt",
    language: "en",
    text: "Fictional high-level fixture: destination authorities publish precautionary traveller guidance and expand syndromic reporting without declaring local transmission.",
    subject: { label: "Singapore travel-health posture", kind: "place" },
    predicate: "destination-monitoring-status",
    object: "precautionary traveller guidance active in frozen scenario",
    targetIndex: 2,
    confidence: 0.88,
    longitude: 103.8198,
    latitude: 1.3521,
    locationLabel: "Singapore",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-news",
    sourceClass: "news",
    title: "Frozen scenario · Dubai transfer-hub disruption report",
    filename: "dubai-transfer-report.txt",
    language: "en",
    text: "Fictional high-level fixture: airlines adjust a small number of connections through a major transfer hub after screening delays, creating possible itinerary changes rather than evidence of exposure.",
    subject: { label: "Dubai transfer corridor", kind: "travel" },
    predicate: "route-disruption-context",
    object: "limited connection changes reported in frozen scenario",
    targetIndex: 2,
    confidence: 0.68,
    longitude: 55.3657,
    latitude: 25.2532,
    locationLabel: "Dubai, United Arab Emirates",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-news",
    sourceClass: "news",
    title: "Frozen scenario · East Africa response network report",
    filename: "east-africa-response.txt",
    language: "en",
    text: "Fictional high-level fixture: regional reporting networks describe intensified triage and data-sharing at transport nodes; the reports remain indirect context for the London targets.",
    subject: { label: "Nairobi response network", kind: "organisation" },
    predicate: "regional-response-status",
    object: "transport-node reporting intensified in frozen scenario",
    targetIndex: 2,
    confidence: 0.64,
    longitude: 36.8219,
    latitude: -1.2921,
    locationLabel: "Nairobi, Kenya",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-news",
    sourceClass: "news",
    title: "Frozen scenario · London household preparedness report",
    filename: "london-preparedness.txt",
    language: "en",
    text: "Fictional high-level fixture: local services emphasise ordinary hygiene, current official advice, and staying home when unwell while the international signal is assessed.",
    subject: { label: "London community preparedness", kind: "group" },
    predicate: "preparedness-guidance-context",
    object: "routine proportionate precautions emphasised",
    targetIndex: 0,
    confidence: 0.7,
    longitude: -0.1276,
    latitude: 51.5072,
    locationLabel: "London, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-news",
    sourceClass: "news",
    title: "Frozen scenario · international air-network movement report",
    filename: "air-network-movement.txt",
    language: "en",
    text: "Fictional high-level fixture: scheduled passenger movements connect the reporting regions with London and Singapore through several hubs; movement alone does not establish risk.",
    subject: { label: "Intercontinental passenger network", kind: "travel" },
    predicate: "movement-network-context",
    object: "London route intersects multiple monitored hubs",
    targetIndex: 2,
    confidence: 0.8,
    longitude: 29.9187,
    latitude: 10.5364,
    locationLabel: "Africa–Europe–Asia corridor",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-social",
    sourceClass: "social",
    title: "Frozen scenario · Heathrow passenger report cluster",
    filename: "heathrow-passenger-posts.txt",
    language: "en",
    text: "Fictional high-level fixture: public posts mention longer screening queues. They are retained as unverified operational leads, not health evidence.",
    subject: { label: "Heathrow public report cluster", kind: "social" },
    predicate: "community-operational-signal",
    object: "unverified screening-delay posts clustered",
    targetIndex: 2,
    confidence: 0.4,
    longitude: -0.4543,
    latitude: 51.47,
    locationLabel: "London Heathrow, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-social",
    sourceClass: "social",
    title: "Frozen scenario · London neighbourhood report cluster",
    filename: "london-neighbourhood-posts.txt",
    language: "en",
    text: "Fictional high-level fixture: scattered public illness mentions are deduplicated and kept below the threshold for a target-impact conclusion.",
    subject: { label: "London public report cluster", kind: "social" },
    predicate: "community-health-signal",
    object: "unverified mentions remain below material threshold",
    targetIndex: 0,
    confidence: 0.36,
    longitude: -0.0877,
    latitude: 51.5074,
    locationLabel: "London, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-social",
    sourceClass: "social",
    title: "Frozen scenario · companion-animal owner report cluster",
    filename: "companion-animal-posts.txt",
    language: "en",
    text: "Fictional high-level fixture: pet-owner posts contain no corroborated unusual veterinary pattern and are treated only as low-confidence leads.",
    subject: { label: "Companion-animal public reports", kind: "animal" },
    predicate: "community-animal-signal",
    object: "no corroborated unusual pattern in frozen scenario",
    targetIndex: 1,
    confidence: 0.34,
    longitude: -0.118,
    latitude: 51.51,
    locationLabel: "London, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-sensor",
    sourceClass: "sensor",
    title: "Frozen scenario · Central Africa syndromic index",
    filename: "central-africa-sensor.txt",
    language: "en",
    text: "Fictional high-level fixture: an aggregated syndromic index rises above its frozen baseline. The abstract index contains no patient records or causal mechanism.",
    subject: { label: "Kinshasa syndromic sensor", kind: "sensor" },
    predicate: "surveillance-index-change",
    object: "aggregated reporting index above frozen baseline",
    targetIndex: 2,
    confidence: 0.84,
    longitude: 15.2663,
    latitude: -4.4419,
    locationLabel: "Kinshasa, Democratic Republic of the Congo",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-sensor",
    sourceClass: "sensor",
    title: "Frozen scenario · Nairobi airport screening index",
    filename: "nairobi-airport-sensor.txt",
    language: "en",
    text: "Fictional high-level fixture: aggregated airport screening counts increase during the scenario window, with no individual-level data retained.",
    subject: { label: "Nairobi airport surveillance", kind: "surveillance-system" },
    predicate: "screening-volume-change",
    object: "aggregated screening volume increased",
    targetIndex: 2,
    confidence: 0.79,
    longitude: 36.9278,
    latitude: -1.3192,
    locationLabel: "Nairobi Airport, Kenya",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-sensor",
    sourceClass: "sensor",
    title: "Frozen scenario · London wastewater reporting index",
    filename: "london-wastewater-sensor.txt",
    language: "en",
    text: "Fictional high-level fixture: an abstract wastewater reporting index changes modestly and remains non-specific; it is environmental context, not household exposure evidence.",
    subject: { label: "London wastewater surveillance", kind: "environment" },
    predicate: "environmental-surveillance-change",
    object: "modest non-specific reporting-index change",
    targetIndex: 0,
    confidence: 0.73,
    longitude: -0.02,
    latitude: 51.49,
    locationLabel: "London, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-sensor",
    sourceClass: "sensor",
    title: "Frozen scenario · Heathrow passenger-flow sensor",
    filename: "heathrow-flow-sensor.txt",
    language: "en",
    text: "Fictional high-level fixture: anonymised passenger-flow counts show the target journey crossing a monitored arrival corridor within fourteen days.",
    subject: { label: "Heathrow passenger-flow system", kind: "sensor" },
    predicate: "target-route-intersection",
    object: "target journey intersects monitored arrival corridor",
    targetIndex: 2,
    confidence: 0.92,
    longitude: -0.4543,
    latitude: 51.47,
    locationLabel: "London Heathrow, United Kingdom",
    licence: "CC0 demo fixture",
  },
  {
    providerId: "demo-custom",
    sourceClass: "custom",
    title: "Frozen scenario · household journey context",
    filename: "household-journey-context.txt",
    language: "en",
    text: "Fictional user context: the household plans to depart Heathrow for Singapore in fourteen days and wants proportionate monitoring before travel.",
    subject: { label: "Household journey plan", kind: "target-context" },
    predicate: "target-travel-context",
    object: "Heathrow to Singapore departure planned in fourteen days",
    targetIndex: 0,
    confidence: 1,
    longitude: -0.4543,
    latitude: 51.47,
    locationLabel: "London Heathrow, United Kingdom",
    licence: "User-provided demo fixture",
  },
  {
    providerId: "demo-custom",
    sourceClass: "custom",
    title: "Frozen scenario · Milo care context",
    filename: "milo-care-context.txt",
    language: "en",
    text: "Fictional user context: Milo remains in London with a known carer during the journey; the household wants animal-health signals kept separate from human travel signals.",
    subject: { label: "Milo care plan", kind: "target-context" },
    predicate: "target-care-context",
    object: "companion animal remains in London during journey",
    targetIndex: 1,
    confidence: 1,
    longitude: -0.1276,
    latitude: 51.5072,
    locationLabel: "London, United Kingdom",
    licence: "User-provided demo fixture",
  },
];

export type BuildWorldOptions = {
  runId: string;
  targetDrafts: TargetDraft[];
  database: BiosecurityDatabase;
  demo?: boolean;
  demoSourceBaseUrl?: string;
  eventDelayMs?: number;
  targetModellingResult?: unknown;
};

const wait = async (milliseconds: number): Promise<void> => {
  if (milliseconds > 0) await new Promise((resolve) => setTimeout(resolve, milliseconds));
};

type BuildEmitter = (
  lane: Lane,
  type: string,
  label: string,
  extras?: Partial<ProcessingEvent>,
) => Promise<ProcessingEvent>;
type LiveRecord = {
  providerId: string;
  sourceClass: SourceArtifact["sourceClass"];
  title: string;
  url: string;
  isolated: IsolatedContent;
  target: Target;
  publishedAt?: string;
  licence: string;
  retrievalMode: "document" | "discovery-metadata";
  explicitlyTargeted?: boolean;
};

type LivePollRecord = LiveRecord & {
  explicitlyTargeted: boolean;
};

type LivePollTask = {
  lane: Lane;
  providerId: string;
  label: string;
  run: () => Promise<LivePollRecord[]>;
};

export function publicSourceQuery(target: Target): string {
  return [target.inferredKind, target.locations[0]?.label, "health surveillance alert"]
    .filter(Boolean)
    .join(" ");
}

async function buildLiveWorld(input: {
  runId: string;
  targets: Target[];
  database: BiosecurityDatabase;
  emit: BuildEmitter;
}): Promise<void> {
  const { runId, targets, database, emit } = input;
  const client = new SafeHttpClient();
  const firstTarget = targets[0]!;
  const coarseQuery = publicSourceQuery(firstTarget);
  const retrieve = async (
    providerId: string,
    sourceClass: SourceArtifact["sourceClass"],
    title: string,
    url: string,
    target: Target,
    licence: string,
  ): Promise<LiveRecord[]> => {
    const { response, body, finalUrl } = await client.fetch(url, { timeoutMs: 12_000 });
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    const isolated = contentType.includes("html")
      ? isolateHtml(body.toString("utf8"))
      : isolateText(body.toString("utf8"), { parser: "public-http" });
    return [
      {
        providerId,
        sourceClass,
        title,
        url: finalUrl,
        isolated,
        target,
        licence,
        retrievalMode: "document",
      },
    ];
  };
  const discoveryRecords = async (
    provider: GdeltDiscoveryProvider | BlueskyPublicDiscoveryProvider,
    target: Target,
    sourceClass: SourceArtifact["sourceClass"],
    licence: string,
  ): Promise<LiveRecord[]> => {
    const discovered = await provider.discover({
      query: coarseQuery,
      language: "en",
      geography: target.locations[0]?.label,
      limit: 8,
    });
    return discovered.map((item) => ({
      providerId: item.providerId,
      sourceClass,
      title: item.title ?? new URL(item.url).hostname,
      url: item.url,
      isolated: isolateText(`${item.title ?? "Public record"}\n${JSON.stringify(item.metadata)}`, {
        discoveryMetadata: true,
      }),
      target,
      ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
      licence,
      retrievalMode: "discovery-metadata" as const,
    }));
  };
  const tasks: Array<{
    lane: Lane;
    providerId: string;
    label: string;
    run: () => Promise<LiveRecord[]>;
  }> = [
    {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "who-don",
      label: "WHO Disease Outbreak News",
      run: () =>
        retrieve(
          "who-don",
          "authority",
          "WHO Disease Outbreak News",
          "https://www.who.int/emergencies/disease-outbreak-news",
          firstTarget,
          "WHO site terms; metadata and lawful excerpt only",
        ),
    },
    {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "uk-fsa-alerts",
      label: "UK Food Standards Agency alerts",
      run: () =>
        retrieve(
          "uk-fsa-alerts",
          "authority",
          "UK Food Standards Agency alerts",
          "https://www.food.gov.uk/news-alerts/search/alerts",
          firstTarget,
          "Source terms; metadata and lawful excerpt only",
        ),
    },
    {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "ncbi-entrez",
      label: "NCBI literature search",
      run: () =>
        retrieve(
          "ncbi-entrez",
          "science",
          `NCBI search · ${coarseQuery}`,
          `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&retmode=json&retmax=20&term=${encodeURIComponent(coarseQuery)}`,
          firstTarget,
          "NCBI record-specific terms",
        ),
    },
    {
      lane: "SENSORS & SURVEILLANCE",
      providerId: "environment-agency-water",
      label: "Environment Agency monitoring stations",
      run: () =>
        retrieve(
          "environment-agency-water",
          "sensor",
          "Environment Agency monitoring stations",
          "https://environment.data.gov.uk/flood-monitoring/id/stations?_limit=20",
          firstTarget,
          "Open Government Licence where marked",
        ),
    },
    {
      lane: "NEWS & OPEN WEB",
      providerId: "gdelt",
      label: "GDELT public news discovery",
      run: () =>
        discoveryRecords(
          new GdeltDiscoveryProvider(),
          firstTarget,
          "news",
          "GDELT terms; original sources retain rights",
        ),
    },
    {
      lane: "SOCIAL & COMMUNITY",
      providerId: "bluesky-public",
      label: "Bluesky public search",
      run: () =>
        discoveryRecords(
          new BlueskyPublicDiscoveryProvider(),
          firstTarget,
          "social",
          "Public-post metadata; original author retains rights",
        ),
    },
  ];
  for (const source of database.listCustomSources(runId)) {
    const target = targets.find((item) => source.targetIds.includes(item.id)) ?? firstTarget;
    if (source.kind === "rss") {
      tasks.push({
        lane: "CUSTOM SOURCES",
        providerId: `custom:${source.id}`,
        label: source.label,
        run: async () => {
          const discovered = await new RssAtomDiscoveryProvider().discover({
            query: source.value,
            limit: 20,
          });
          return discovered.map((item) => ({
            providerId: `custom:${source.id}`,
            sourceClass: "custom" as const,
            title: item.title ?? new URL(item.url).hostname,
            url: item.url,
            isolated: isolateText(
              `${item.title ?? "Feed item"}\n${JSON.stringify(item.metadata)}`,
              { customSourceId: source.id },
            ),
            target,
            ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
            licence: "Custom source; original record terms apply",
            retrievalMode: "discovery-metadata" as const,
            explicitlyTargeted: source.targetIds.includes(target.id),
          }));
        },
      });
    } else if (["url", "rest", "graphql", "sitemap"].includes(source.kind)) {
      tasks.push({
        lane: "CUSTOM SOURCES",
        providerId: `custom:${source.id}`,
        label: source.label,
        run: () =>
          retrieve(
            `custom:${source.id}`,
            "custom",
            source.label,
            source.value,
            target,
            "Custom source; original terms apply",
          ).then((records) =>
            records.map((record) => ({
              ...record,
              explicitlyTargeted: source.targetIds.includes(target.id),
            })),
          ),
      });
    }
  }

  const records =
    process.env.BIOSECURITY_OFFLINE === "true"
      ? []
      : (
          await Promise.all(
            tasks.map(async (task) => {
              await emit(task.lane, "source.search.started", `${task.label} search started`, {
                status: "started",
                metadata: { providerId: task.providerId },
              });
              try {
                const found = await task.run();
                await emit(
                  task.lane,
                  "source.searched",
                  `${task.label} returned ${found.length} record${found.length === 1 ? "" : "s"}`,
                  {
                    countDelta: 1,
                    metadata: { providerId: task.providerId, discovered: found.length },
                  },
                );
                return found;
              } catch (error) {
                const message = (error as Error).message;
                const classification = message.includes("HTTP 429")
                  ? { type: "source.rate-limited", label: "rate limited" }
                  : /HTTP (401|403)/.test(message)
                    ? { type: "source.access-limited", label: "access limited" }
                    : { type: "source.failed", label: "unavailable" };
                await emit(
                  task.lane,
                  classification.type,
                  `${task.label} ${classification.label}: ${message}`,
                  { status: "failed", metadata: { providerId: task.providerId } },
                );
                return [];
              }
            }),
          )
        ).flat();

  if (process.env.BIOSECURITY_OFFLINE === "true") {
    await emit(
      "OFFICIAL & SCIENTIFIC",
      "source.offline",
      "Network retrieval disabled by BIOSECURITY_OFFLINE=true",
      { metadata: { configuredProviders: tasks.length } },
    );
  }

  const artifacts: SourceArtifact[] = [];
  const claims: Claim[] = [];
  const entities: Entity[] = [];
  const evidence: EvidenceRecord[] = [];
  for (const record of records.slice(0, 80)) {
    const publishedAt = normalizeExternalPublishedAt(record.publishedAt);
    const artifact = SourceArtifactSchema.parse({
      id: `artifact_${nanoid(10)}`,
      providerId: record.providerId,
      sourceClass: record.sourceClass,
      url: record.url,
      title: record.title,
      language: "en",
      ...(publishedAt ? { publishedAt } : {}),
      retrievedAt: new Date().toISOString(),
      contentHash: record.isolated.contentHash,
      rawStorageRef: `sha256:${record.isolated.contentHash}`,
      licence: record.licence,
      redistribution: "Metadata and short evidence excerpt only",
      trustMetadata: {
        untrusted: true,
        live: true,
        retrievalMode: record.retrievalMode,
        findings: record.isolated.findings,
      },
      securityState: record.isolated.securityState,
    });
    database.saveArtifact(runId, artifact, record.isolated.text);
    artifacts.push(artifact);
    await emit(
      record.sourceClass === "news"
        ? "NEWS & OPEN WEB"
        : record.sourceClass === "social"
          ? "SOCIAL & COMMUNITY"
          : record.sourceClass === "sensor"
            ? "SENSORS & SURVEILLANCE"
            : record.sourceClass === "custom"
              ? "CUSTOM SOURCES"
              : "OFFICIAL & SCIENTIFIC",
      record.retrievalMode === "document" ? "artifact.retrieved" : "url.discovered",
      record.retrievalMode === "document"
        ? `${record.title} document retrieved, persisted, and isolated`
        : `${record.title} discovery metadata persisted and isolated`,
      { artifactId: artifact.id, metadata: { providerId: record.providerId } },
    );
    if (artifact.securityState !== "accepted") continue;
    const entity = EntitySchema.parse({
      id: `entity_${nanoid(10)}`,
      label: record.title,
      kind: "document",
      aliases: [],
      attributes: { providerId: record.providerId, live: true },
      locations: [],
    });
    database.saveEntity(runId, entity);
    entities.push(entity);
    await emit(
      "WORLD SYNTHESIS",
      "entity.resolved",
      `${record.title} resolved as a source entity`,
      { entityId: entity.id, artifactId: artifact.id },
    );
    const claim = ClaimSchema.parse({
      id: `claim_${nanoid(10)}`,
      artifactId: artifact.id,
      subject: { id: entity.id, label: entity.label, kind: entity.kind },
      predicate:
        record.retrievalMode === "document"
          ? "retrieved-for-target-query"
          : "discovered-for-target-query",
      object: record.target.name,
      evidenceSpan: { excerpt: record.isolated.text.slice(0, 700) },
      confidence:
        record.sourceClass === "authority" || record.sourceClass === "science"
          ? 0.72
          : record.sourceClass === "social"
            ? 0.35
            : 0.52,
      state: "observed",
    });
    database.saveClaim(runId, claim);
    claims.push(claim);
    await emit(
      "WORLD SYNTHESIS",
      "claim.extracted",
      `${record.retrievalMode === "document" ? "Retrieval" : "Discovery"} provenance claim retained for ${record.title}`,
      { entityId: entity.id, artifactId: artifact.id },
    );
    const lexicalMatches = targetTermMatches(record.target, record.isolated.text);
    const explicitlyTargeted = record.explicitlyTargeted === true;
    const material = isMaterialTargetContent(record.target, record.isolated.text, {
      explicitlyTargeted,
      retrievalMode: record.retrievalMode,
    });
    await emit(
      "WORLD SYNTHESIS",
      material ? "target.linked" : "target.evaluated",
      material
        ? `${record.title} linked to ${record.target.name}`
        : `${record.title} retained as non-material for ${record.target.name}`,
      {
        entityId: record.target.id,
        artifactId: artifact.id,
        metadata: { explicitlyTargeted, lexicalMatches, material },
      },
    );
    const evidenceRecord = EvidenceRecordSchema.parse({
      id: `evidence_${nanoid(10)}`,
      sourceTitle: record.title,
      sourceUrl: artifact.url,
      sourceClass: record.sourceClass,
      excerpt: record.isolated.text.slice(0, 700),
      ...(publishedAt ? { publishedAt } : {}),
      retrievedAt: artifact.retrievedAt,
      geographicResolution: record.target.locations[0]?.resolution ?? "unknown",
      language: "en",
      claim:
        record.retrievalMode === "document"
          ? `${record.title} was retrieved from ${record.providerId} for the target query. Content relevance requires review.`
          : `${record.title} was discovered through ${record.providerId} for the target query. Only discovery metadata was retained; source content was not retrieved.`,
      supportingEvidenceIds: [],
      contradictingEvidenceIds: [],
      targetIds: [record.target.id],
      targetRelevance: material
        ? `${explicitlyTargeted ? "Explicitly scoped and " : ""}matched ${lexicalMatches} target term${lexicalMatches === 1 ? "" : "s"} for ${record.target.name}`
        : `No material lexical match to ${record.target.name}`,
      material,
      confidence: claim.confidence,
      status: "observed",
      licenceNotes: record.licence,
    });
    database.saveEvidence(runId, evidenceRecord);
    evidence.push(evidenceRecord);
  }

  for (const target of targets) {
    const relevantProviders = new Set(
      records
        .filter(
          (record) =>
            record.target.id === target.id &&
            isMaterialTargetContent(record.target, record.isolated.text, {
              explicitlyTargeted: record.explicitlyTargeted === true,
              retrievalMode: record.retrievalMode,
            }),
        )
        .map((record) => record.providerId),
    );
    if (relevantProviders.size > 1) {
      await emit(
        "WORLD SYNTHESIS",
        "relationship.created",
        `${relevantProviders.size} independent providers retained for ${target.name}`,
        {
          countDelta: relevantProviders.size - 1,
          entityId: target.id,
          metadata: { providers: [...relevantProviders] },
        },
      );
    }
  }

  for (const target of targets) {
    const watcher = {
      id: `watcher_${nanoid(10)}`,
      runId,
      targetIds: [target.id],
      query: buildInvestigationPlan(target)[0]!.query,
      sourceProviders: tasks.map((task) => task.providerId),
      cadence: 900,
      language: "en",
      geography: target.locations[0]?.label ?? "unspecified",
      cursor: null,
      lastSuccessfulRun: null,
      lastMaterialUpdate: null,
      health: "starting" as const,
    };
    database.saveWatcher(watcher);
    await emit("LIVE WATCH", "watcher.created", `Watcher created for ${target.name}`, {
      entityId: target.id,
    });
  }
  const snapshot = WorldSnapshotSchema.parse({
    id: `snapshot_${nanoid(12)}`,
    worldId: `world_${runId}`,
    asOf: new Date().toISOString(),
    targetIds: targets.map((target) => target.id),
    entityIds: entities.map((entity) => entity.id),
    claimIds: claims.map((claim) => claim.id),
    materialChanges: [],
    protectionIds: [],
    coverage: {
      searchedClasses: [...new Set(artifacts.map((artifact) => artifact.sourceClass))],
      unavailableProviders: tasks
        .filter((task) => !artifacts.some((artifact) => artifact.providerId === task.providerId))
        .map((task) => task.providerId),
      languages: artifacts.length ? ["en"] : [],
      limitations: [
        "Public-source availability varies; retrieval is bounded and failures are retained as processing events",
        "Retrieved-for-query provenance is not evidence of exposure, diagnosis, or causation",
      ],
    },
    provenance: {
      artifactIds: artifacts.map((artifact) => artifact.id),
      observedClaims: claims.length,
    },
  });
  database.saveSnapshot(runId, snapshot);
  await emit(
    "WORLD SYNTHESIS",
    "snapshot.created",
    "Target-centred live-source snapshot persisted",
    { metadata: { snapshotId: snapshot.id, artifacts: artifacts.length } },
  );
  database.updateRunPhase(runId, "live");
  await emit("LIVE WATCH", "world.live", "World construction complete · live tracking active");
}

export function targetTermMatches(target: Target, text: string): number {
  const genericTerms = new Set([
    "about",
    "affecting",
    "conditions",
    "guidance",
    "health",
    "public",
  ]);
  const terms = `${target.name} ${target.description} ${target.inferredKind ?? ""}`
    .toLowerCase()
    .split(/\W+/)
    .filter((term) => term.length >= 4 && !genericTerms.has(term));
  // Match complete lexical tokens. Substring matching made words such as
  // "plant" eligible to match unrelated text fragments and amplified noisy
  // discovery metadata into material state changes.
  const haystackTerms = new Set(text.toLowerCase().split(/\W+/).filter(Boolean));
  return new Set(terms.filter((term) => haystackTerms.has(term))).size;
}

export function isMaterialTargetContent(
  target: Target,
  text: string,
  options: {
    explicitlyTargeted?: boolean;
    retrievalMode: "document" | "discovery-metadata";
  },
): boolean {
  const matches = targetTermMatches(target, text);
  if (options.explicitlyTargeted) return matches > 0;
  // Discovery search terms necessarily contain broad target geography and
  // category words. Requiring three independent exact terms keeps a place-name
  // pair (for example "United Kingdom") from becoming a material alert by
  // itself while retaining strongly target-specific discoveries.
  return options.retrievalMode === "discovery-metadata" && matches >= 3;
}

function customSourceApplies(source: CustomSource, target: Target): boolean {
  return source.enabled && (!source.targetIds.length || source.targetIds.includes(target.id));
}

/**
 * Re-poll the registered source set for one persisted watcher. New records cross the
 * same isolated-content and structured-evidence boundary used by the initial build.
 */
export async function pollLiveWatcher(
  database: BiosecurityDatabase,
  watcher: Watcher,
): Promise<{
  cursor: string;
  material: boolean;
  summary?: string;
  artifactIds: string[];
  entityIds: string[];
  claimIds: string[];
  materialClaimIds: string[];
  evidenceIds: string[];
}> {
  const target = database
    .listTargets(watcher.runId)
    .find((item) => watcher.targetIds.includes(item.id));
  if (!target) throw new Error("Watcher target no longer exists");

  const client = new SafeHttpClient();
  const direct = new DirectHttpRetrievalProvider();
  const tasks: LivePollTask[] = [];
  const publicQuery = publicSourceQuery(target);
  const emit = (
    lane: Lane,
    type: string,
    label: string,
    status: ProcessingEvent["status"],
    metadata: Record<string, unknown>,
    extras: Partial<ProcessingEvent> = {},
  ): void =>
    database.saveEvent(
      ProcessingEventSchema.parse({
        id: `event_watch_${nanoid(10)}`,
        runId: watcher.runId,
        lane,
        type,
        status,
        label,
        createdAt: new Date().toISOString(),
        metadata: { watcherId: watcher.id, ...metadata },
        ...extras,
      }),
    );

  if (process.env.BIOSECURITY_OFFLINE === "true") {
    emit(
      "LIVE WATCH",
      "source.offline",
      "Live source polling disabled by BIOSECURITY_OFFLINE=true",
      "completed",
      {},
    );
    return {
      cursor: watcher.cursor ?? `offline:${new Date().toISOString()}`,
      material: false,
      artifactIds: [],
      entityIds: [],
      claimIds: [],
      materialClaimIds: [],
      evidenceIds: [],
    };
  }

  const retrieve = async (
    providerId: string,
    sourceClass: SourceArtifact["sourceClass"],
    title: string,
    url: string,
    licence: string,
    explicitlyTargeted = false,
  ): Promise<LivePollRecord[]> => {
    const { response, body, finalUrl } = await client.fetch(url, { timeoutMs: 12_000 });
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    const isolated = contentType.includes("html")
      ? isolateHtml(body.toString("utf8"))
      : isolateText(body.toString("utf8"), { parser: "live-public-http" });
    return [
      {
        providerId,
        sourceClass,
        title,
        url: finalUrl,
        isolated,
        target,
        licence,
        retrievalMode: "document",
        explicitlyTargeted,
      },
    ];
  };

  const discover = async (
    provider: GdeltDiscoveryProvider | BlueskyPublicDiscoveryProvider,
    sourceClass: SourceArtifact["sourceClass"],
    licence: string,
  ): Promise<LivePollRecord[]> =>
    (
      await provider.discover({
        query: publicQuery,
        language: watcher.language,
        geography: watcher.geography,
        cursor: watcher.cursor ?? undefined,
        limit: 8,
      })
    ).map((item) => ({
      providerId: item.providerId,
      sourceClass,
      title: item.title ?? new URL(item.url).hostname,
      url: item.url,
      isolated: isolateText(`${item.title ?? "Public record"}\n${JSON.stringify(item.metadata)}`, {
        discoveryMetadata: true,
      }),
      target,
      ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
      licence,
      retrievalMode: "discovery-metadata" as const,
      explicitlyTargeted: false,
    }));

  const builtIns: Record<string, LivePollTask> = {
    "who-don": {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "who-don",
      label: "WHO Disease Outbreak News",
      run: () =>
        retrieve(
          "who-don",
          "authority",
          "WHO Disease Outbreak News",
          "https://www.who.int/emergencies/disease-outbreak-news",
          "WHO site terms; metadata and lawful excerpt only",
        ),
    },
    "uk-fsa-alerts": {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "uk-fsa-alerts",
      label: "UK Food Standards Agency alerts",
      run: () =>
        retrieve(
          "uk-fsa-alerts",
          "authority",
          "UK Food Standards Agency alerts",
          "https://www.food.gov.uk/news-alerts/search/alerts",
          "Source terms; metadata and lawful excerpt only",
        ),
    },
    "ncbi-entrez": {
      lane: "OFFICIAL & SCIENTIFIC",
      providerId: "ncbi-entrez",
      label: "NCBI literature search",
      run: () =>
        retrieve(
          "ncbi-entrez",
          "science",
          `NCBI search · ${publicQuery}`,
          `https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&retmode=json&retmax=20&term=${encodeURIComponent(publicQuery)}`,
          "NCBI record-specific terms",
        ),
    },
    "environment-agency-water": {
      lane: "SENSORS & SURVEILLANCE",
      providerId: "environment-agency-water",
      label: "Environment Agency monitoring stations",
      run: () =>
        retrieve(
          "environment-agency-water",
          "sensor",
          "Environment Agency monitoring stations",
          "https://environment.data.gov.uk/flood-monitoring/id/stations?_limit=20",
          "Open Government Licence where marked",
        ),
    },
    gdelt: {
      lane: "NEWS & OPEN WEB",
      providerId: "gdelt",
      label: "GDELT public news discovery",
      run: () =>
        discover(
          new GdeltDiscoveryProvider(),
          "news",
          "GDELT terms; original sources retain rights",
        ),
    },
    "bluesky-public": {
      lane: "SOCIAL & COMMUNITY",
      providerId: "bluesky-public",
      label: "Bluesky public search",
      run: () =>
        discover(
          new BlueskyPublicDiscoveryProvider(),
          "social",
          "Public-post metadata; original author retains rights",
        ),
    },
  };
  for (const providerId of watcher.sourceProviders) {
    const task = builtIns[providerId];
    if (task) tasks.push(task);
  }

  for (const source of database
    .listCustomSources(watcher.runId)
    .filter((item) => customSourceApplies(item, target))) {
    const explicitlyTargeted = source.targetIds.includes(target.id);
    if (source.kind === "rss") {
      tasks.push({
        lane: "CUSTOM SOURCES",
        providerId: `custom:${source.id}`,
        label: source.label,
        run: async () =>
          (await new RssAtomDiscoveryProvider().discover({ query: source.value, limit: 20 })).map(
            (item) => ({
              providerId: `custom:${source.id}`,
              sourceClass: "custom" as const,
              title: item.title ?? new URL(item.url).hostname,
              url: item.url,
              isolated: isolateText(
                `${item.title ?? "Feed item"}\n${JSON.stringify(item.metadata)}`,
                { customSourceId: source.id, discoveryMetadata: true },
              ),
              target,
              ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
              licence: "Custom feed; original record terms apply",
              retrievalMode: "discovery-metadata" as const,
              explicitlyTargeted,
            }),
          ),
      });
    } else if (source.kind === "sitemap") {
      tasks.push({
        lane: "CUSTOM SOURCES",
        providerId: `custom:${source.id}`,
        label: source.label,
        run: async () =>
          (
            await new XmlSitemapDiscoveryProvider().discover({ query: source.value, limit: 20 })
          ).map((item) => ({
            providerId: `custom:${source.id}`,
            sourceClass: "custom" as const,
            title: item.title ?? new URL(item.url).hostname,
            url: item.url,
            isolated: isolateText(
              `${item.title ?? "Sitemap record"}\n${JSON.stringify(item.metadata)}`,
              { customSourceId: source.id, discoveryMetadata: true },
            ),
            target,
            ...(item.publishedAt ? { publishedAt: item.publishedAt } : {}),
            licence: "Custom sitemap; original record terms apply",
            retrievalMode: "discovery-metadata" as const,
            explicitlyTargeted,
          })),
      });
    } else if (["url", "rest", "graphql"].includes(source.kind)) {
      tasks.push({
        lane: "CUSTOM SOURCES",
        providerId: `custom:${source.id}`,
        label: source.label,
        run: async () => {
          const result = await direct.retrieve({ url: source.value });
          return [
            {
              providerId: `custom:${source.id}`,
              sourceClass: "custom" as const,
              title: result.artifact.title ?? source.label,
              url: result.artifact.url ?? source.value,
              isolated: result.isolated,
              target,
              licence: "Custom source; original terms apply",
              retrievalMode: "document" as const,
              explicitlyTargeted,
            },
          ];
        },
      });
    }
  }

  const outcomes = await Promise.all(
    tasks.map(async (task): Promise<LivePollRecord[] | undefined> => {
      emit(task.lane, "watcher.source.started", `${task.label} live poll started`, "started", {
        providerId: task.providerId,
      });
      try {
        const found = await task.run();
        emit(
          task.lane,
          "watcher.source.polled",
          `${task.label} live poll returned ${found.length} record${found.length === 1 ? "" : "s"}`,
          "completed",
          { providerId: task.providerId, discovered: found.length },
        );
        return found;
      } catch (error) {
        const message = (error as Error).message;
        const classification = message.includes("HTTP 429")
          ? { type: "source.rate-limited", label: "rate limited" }
          : /HTTP (401|403)/.test(message)
            ? { type: "source.access-limited", label: "access limited" }
            : { type: "source.failed", label: "unavailable" };
        emit(
          task.lane,
          classification.type,
          `${task.label} live poll ${classification.label}: ${message}`,
          "failed",
          { providerId: task.providerId },
        );
        return undefined;
      }
    }),
  );
  const successfulTasks = outcomes.filter((item) => item !== undefined).length;
  const records = outcomes.flatMap((item) => item ?? []);
  if (tasks.length && !successfulTasks) throw new Error("Every registered live source poll failed");

  const existing = database.listArtifacts(watcher.runId);
  const artifactIds: string[] = [];
  const entityIds: string[] = [];
  const claimIds: string[] = [];
  const materialClaimIds: string[] = [];
  const evidenceIds: string[] = [];
  const materialTitles: string[] = [];
  for (const record of records) {
    const known = existing.some(
      (artifact) =>
        artifact.url === record.url &&
        (record.retrievalMode === "discovery-metadata" ||
          artifact.contentHash === record.isolated.contentHash),
    );
    if (known) continue;
    const retrievedAt = new Date().toISOString();
    const publishedAt = normalizeExternalPublishedAt(record.publishedAt);
    const artifact = SourceArtifactSchema.parse({
      id: `artifact_${nanoid(10)}`,
      providerId: record.providerId,
      sourceClass: record.sourceClass,
      url: record.url,
      title: record.title,
      language: watcher.language,
      ...(publishedAt ? { publishedAt } : {}),
      retrievedAt,
      contentHash: record.isolated.contentHash,
      rawStorageRef: `sha256:${record.isolated.contentHash}`,
      licence: record.licence,
      redistribution: "Metadata and short evidence excerpt only",
      trustMetadata: {
        untrusted: true,
        live: true,
        retrievalMode: record.retrievalMode,
        watcherId: watcher.id,
        findings: record.isolated.findings,
      },
      securityState: record.isolated.securityState,
    });
    database.saveArtifact(watcher.runId, artifact, record.isolated.text);
    artifactIds.push(artifact.id);
    emit(
      record.sourceClass === "custom" ? "CUSTOM SOURCES" : "LIVE WATCH",
      record.retrievalMode === "document" ? "artifact.retrieved" : "url.discovered",
      record.retrievalMode === "document"
        ? `${record.title} live document retrieved, persisted, and isolated`
        : `${record.title} live discovery metadata persisted and isolated`,
      "completed",
      { providerId: record.providerId, retrievalMode: record.retrievalMode },
      { artifactId: artifact.id },
    );
    if (artifact.securityState !== "accepted") continue;

    const entity = EntitySchema.parse({
      id: `entity_${nanoid(10)}`,
      label: record.title,
      kind: "document",
      aliases: [],
      attributes: { providerId: record.providerId, live: true, watcherId: watcher.id },
      locations: [],
    });
    database.saveEntity(watcher.runId, entity);
    entityIds.push(entity.id);
    emit(
      "WORLD SYNTHESIS",
      "entity.resolved",
      `${record.title} resolved as a live source entity`,
      "completed",
      {
        providerId: record.providerId,
      },
      { entityId: entity.id, artifactId: artifact.id },
    );

    const claim = ClaimSchema.parse({
      id: `claim_${nanoid(10)}`,
      artifactId: artifact.id,
      subject: { id: entity.id, label: entity.label, kind: entity.kind },
      predicate:
        record.retrievalMode === "document"
          ? "live-retrieved-for-target-query"
          : "live-discovered-for-target-query",
      object: target.name,
      evidenceSpan: { excerpt: record.isolated.text.slice(0, 700) },
      confidence: record.sourceClass === "authority" ? 0.72 : 0.52,
      state: "observed",
    });
    database.saveClaim(watcher.runId, claim);
    claimIds.push(claim.id);
    emit(
      "WORLD SYNTHESIS",
      "claim.extracted",
      `Observed live provenance claim retained for ${record.title}`,
      "completed",
      {
        providerId: record.providerId,
      },
      { entityId: entity.id, artifactId: artifact.id },
    );

    const explicit = record.explicitlyTargeted;
    const lexicalMatches = targetTermMatches(target, record.isolated.text);
    const lexical = lexicalMatches >= 2;
    const material = isMaterialTargetContent(target, record.isolated.text, {
      explicitlyTargeted: explicit,
      retrievalMode: record.retrievalMode,
    });
    const evidenceRecord = EvidenceRecordSchema.parse({
      id: `evidence_${nanoid(10)}`,
      sourceTitle: record.title,
      sourceUrl: artifact.url,
      sourceClass: record.sourceClass,
      excerpt: record.isolated.text.slice(0, 700),
      ...(publishedAt ? { publishedAt } : {}),
      retrievedAt,
      geographicResolution: target.locations[0]?.resolution ?? "unknown",
      language: watcher.language,
      claim: `${record.title} is a newly persisted ${record.retrievalMode === "document" ? "document" : "discovery record"} from ${record.providerId}.`,
      supportingEvidenceIds: [],
      contradictingEvidenceIds: [],
      targetIds: [target.id],
      targetRelevance:
        explicit && lexicalMatches > 0
          ? `Explicitly scoped by the user to ${target.name}; matched ${lexicalMatches} target term${lexicalMatches === 1 ? "" : "s"}`
          : explicit
            ? `Explicitly scoped by the user to ${target.name}, but no target term matched; retained as non-material`
            : lexical
              ? `Lexical match to multiple terms for ${target.name}`
              : `No material lexical match to ${target.name}`,
      material,
      confidence: claim.confidence,
      status: "observed",
      licenceNotes: record.licence,
    });
    database.saveEvidence(watcher.runId, evidenceRecord);
    emit(
      "WORLD SYNTHESIS",
      material ? "target.linked" : "target.evaluated",
      material
        ? `${record.title} linked to ${target.name}`
        : `${record.title} retained as non-material for ${target.name}`,
      "completed",
      {
        providerId: record.providerId,
        explicitlyTargeted: explicit,
        lexicalMatch: lexical,
      },
      { entityId: target.id, artifactId: artifact.id },
    );

    if (material) {
      materialTitles.push(record.title);
      materialClaimIds.push(claim.id);
      evidenceIds.push(evidenceRecord.id);
    }
  }

  const uniqueTitles = [...new Set(materialTitles)];
  return {
    cursor: `poll:${new Date().toISOString()}`,
    material: uniqueTitles.length > 0,
    ...(uniqueTitles.length
      ? {
          summary: `${uniqueTitles.length} new target-relevant source record${uniqueTitles.length === 1 ? "" : "s"} persisted: ${uniqueTitles.slice(0, 3).join("; ")}`,
        }
      : {}),
    artifactIds,
    entityIds,
    claimIds,
    materialClaimIds,
    evidenceIds,
  };
}

export async function buildDeterministicWorld(options: BuildWorldOptions): Promise<void> {
  const { runId, database, demo = false, eventDelayMs = 35 } = options;
  const demoSourceBaseUrl = options.demoSourceBaseUrl ?? "http://127.0.0.1:7331";
  let eventSequence = 0;
  const emit = async (
    lane: Lane,
    type: string,
    label: string,
    extras: Partial<ProcessingEvent> = {},
  ): Promise<ProcessingEvent> => {
    eventSequence += 1;
    const event = ProcessingEventSchema.parse({
      id: `event_${runId}_${eventSequence.toString().padStart(4, "0")}`,
      runId,
      lane,
      type,
      status: "completed",
      label,
      createdAt: new Date(Date.now() + eventSequence).toISOString(),
      metadata: {},
      ...extras,
    });
    database.saveEvent(event);
    await wait(eventDelayMs);
    return event;
  };

  try {
    const parsedAgentResult = TargetModellingResultSchema.safeParse(options.targetModellingResult);
    const targets = modelTargets(
      options.targetDrafts,
      new Date().toISOString(),
      parsedAgentResult.success ? parsedAgentResult.data : undefined,
    );
    for (const target of targets) {
      database.saveTarget(runId, target);
      await emit(
        "TARGET MODELLING",
        "target.modelled",
        `${target.name} structured as ${target.inferredKind}`,
        {
          entityId: target.id,
          metadata: {
            inferredKind: target.inferredKind,
            locations: target.locations.map((location) => location.label),
          },
        },
      );
      for (const query of buildInvestigationPlan(target)) {
        await emit(
          "TARGET MODELLING",
          "query.created",
          `Query created · ${query.language.toUpperCase()} · ${query.query}`,
          {
            metadata: { language: query.language, targetId: target.id, query: query.query },
          },
        );
      }
    }

    if (!demo) {
      await buildLiveWorld({ runId, targets, database, emit });
      return;
    }

    const facts = DEMO_FACTS;
    const artifacts: SourceArtifact[] = [];
    const claims: Claim[] = [];
    const entities: Entity[] = [];
    const evidence: EvidenceRecord[] = [];
    const factArtifacts: Array<{ fact: DemoFact; artifact: SourceArtifact }> = [];

    for (const fact of facts) {
      const lane: Lane =
        fact.sourceClass === "authority" || fact.sourceClass === "science"
          ? "OFFICIAL & SCIENTIFIC"
          : fact.sourceClass === "news"
            ? "NEWS & OPEN WEB"
            : fact.sourceClass === "social"
              ? "SOCIAL & COMMUNITY"
              : fact.sourceClass === "sensor"
                ? "SENSORS & SURVEILLANCE"
                : "CUSTOM SOURCES";
      await emit(lane, "source.searched", `${fact.title} searched`, {
        metadata: { providerId: fact.providerId },
      });
      const isolated = isolateText(fact.text, { fixture: true, fictional: true });
      const artifact = SourceArtifactSchema.parse({
        id: `artifact_${nanoid(10)}`,
        providerId: fact.providerId,
        sourceClass: fact.sourceClass,
        url: `${demoSourceBaseUrl}/demo/sources/${fact.filename}`,
        title: fact.title,
        language: fact.language,
        publishedAt: "2026-08-01T09:00:00.000Z",
        retrievedAt: new Date().toISOString(),
        contentHash: isolated.contentHash,
        rawStorageRef: `builtin:demo/${fact.filename}`,
        licence: fact.licence,
        redistribution: "Full fixture redistribution permitted",
        trustMetadata: {
          untrusted: true,
          fixture: true,
          fictional: true,
          findings: isolated.findings,
        },
        securityState: isolated.securityState,
      });
      database.saveArtifact(runId, artifact, isolated.text);
      artifacts.push(artifact);
      await emit(lane, "artifact.retrieved", `${fact.title} retrieved and isolated`, {
        artifactId: artifact.id,
      });
      await emit(lane, "language.detected", `Language detected · ${fact.language.toUpperCase()}`, {
        artifactId: artifact.id,
        metadata: { language: fact.language },
      });
      factArtifacts.push({ fact, artifact });
    }

    for (const { fact, artifact } of factArtifacts) {
      const entity = EntitySchema.parse({
        id: `entity_${nanoid(10)}`,
        label: fact.subject.label,
        kind: fact.subject.kind,
        aliases: [],
        attributes: { fixture: true },
        locations: [
          {
            id: `loc_${nanoid(8)}`,
            label: fact.locationLabel,
            latitude: fact.latitude,
            longitude: fact.longitude,
            resolution: "locality",
          },
        ],
      });
      const resolved = resolveEntity(entities, entity);
      if (!resolved.merged) entities.push(resolved.entity);
      else {
        const index = entities.findIndex((item) => item.id === resolved.entity.id);
        entities[index] = resolved.entity;
      }
      database.saveEntity(runId, resolved.entity);
      await emit("WORLD SYNTHESIS", "entity.resolved", `${fact.subject.label} resolved`, {
        entityId: resolved.entity.id,
      });

      const claim = ClaimSchema.parse({
        id: `claim_${nanoid(10)}`,
        artifactId: artifact.id,
        subject: {
          id: resolved.entity.id,
          label: resolved.entity.label,
          kind: resolved.entity.kind,
        },
        predicate: fact.predicate,
        object: fact.object,
        time: { label: "frozen fixture date", start: "2024-06-14T09:00:00.000Z" },
        geography: resolved.entity.locations[0],
        evidenceSpan: { excerpt: fact.text },
        confidence: fact.confidence,
        state: "observed",
      });
      database.saveClaim(runId, claim);
      claims.push(claim);
      await emit("WORLD SYNTHESIS", "claim.extracted", `${fact.predicate} claim extracted`, {
        entityId: resolved.entity.id,
        artifactId: artifact.id,
      });

      const target = targets[fact.targetIndex] ?? targets[0]!;
      const relevance = targetRelevance(target, claim);
      await emit(
        "WORLD SYNTHESIS",
        "target.linked",
        `${fact.subject.label} linked to ${target.name}`,
        {
          entityId: target.id,
          artifactId: artifact.id,
          metadata: { relevance },
        },
      );
      await emit(
        "WORLD SYNTHESIS",
        "relationship.created",
        `${fact.subject.label} connected to ${target.name}`,
        {
          entityId: resolved.entity.id,
          artifactId: artifact.id,
          metadata: {
            targetId: target.id,
            claimId: claim.id,
            relation: "target-relevant-context",
          },
        },
      );
      const evidenceRecord = EvidenceRecordSchema.parse({
        id: `evidence_${nanoid(10)}`,
        sourceTitle: fact.title,
        sourceUrl: artifact.url,
        sourceClass: fact.sourceClass,
        excerpt: fact.text,
        publishedAt: artifact.publishedAt,
        retrievedAt: artifact.retrievedAt,
        geographicResolution: "locality",
        language: fact.language,
        claim: `${fact.subject.label} ${fact.predicate}: ${fact.object}`,
        supportingEvidenceIds: [],
        contradictingEvidenceIds: [],
        targetIds: [target.id],
        targetRelevance: `${Math.round(relevance * 100)}% lexical and geographic relevance to ${target.name}`,
        material: true,
        confidence: fact.confidence,
        status: "observed",
        licenceNotes: fact.licence,
      });
      evidence.push(evidenceRecord);
      database.saveEvidence(runId, evidenceRecord);
    }

    const duplicateClusters = deduplicateArtifacts(artifacts).filter(
      (cluster) => cluster.duplicates.length > 0,
    );
    for (const cluster of duplicateClusters) {
      await emit(
        "WORLD SYNTHESIS",
        "duplicate.merged",
        `${cluster.duplicates.length + 1} identical artifacts clustered`,
        {
          artifactId: cluster.primary.id,
        },
      );
    }
    const corroboratedClaims = claims.filter(
      (claim) => estimateCorroboration(claim, claims, artifacts) > claim.confidence,
    );
    for (const claim of corroboratedClaims) {
      await emit(
        "WORLD SYNTHESIS",
        "relationship.created",
        `Independent evidence relationship created for ${claim.subject.label}`,
        {
          entityId: claim.subject.id,
          artifactId: claim.artifactId,
        },
      );
    }
    const contradictions = detectContradictions(claims);
    for (const contradiction of contradictions) {
      await emit(
        "WORLD SYNTHESIS",
        "source.conflict",
        "Conflicting claim objects retained for review",
        { metadata: contradiction },
      );
    }

    const watcherProviders = demo
      ? ["demo-official", "demo-science", "demo-news", "demo-social", "demo-sensor"]
      : ["who-don", "uk-fsa-alerts", "ncbi-entrez"];
    for (const target of targets) {
      const watcher = {
        id: `watcher_${nanoid(10)}`,
        runId,
        targetIds: [target.id],
        query: buildInvestigationPlan(target)[0]!.query,
        sourceProviders: watcherProviders,
        cadence: demo ? 300 : 900,
        language: "en",
        geography: target.locations[0]?.label ?? "unspecified",
        cursor: null,
        lastSuccessfulRun: null,
        lastMaterialUpdate: null,
        health: "starting" as const,
      };
      database.saveWatcher(watcher);
      await emit("LIVE WATCH", "watcher.created", `Watcher created for ${target.name}`, {
        entityId: target.id,
      });
    }

    const snapshot = WorldSnapshotSchema.parse({
      id: `snapshot_${nanoid(12)}`,
      worldId: `world_${runId}`,
      asOf: new Date().toISOString(),
      targetIds: targets.map((target) => target.id),
      entityIds: entities.map((entity) => entity.id),
      claimIds: claims.map((claim) => claim.id),
      materialChanges: [],
      protectionIds: [],
      coverage: {
        searchedClasses: [...new Set(artifacts.map((artifact) => artifact.sourceClass))],
        unavailableProviders: demo ? [] : ["searxng", "mastodon-public"],
        languages: [
          ...new Set(
            artifacts.flatMap((artifact) => (artifact.language ? [artifact.language] : [])),
          ),
        ],
        limitations: demo
          ? ["Frozen fictional fixture; no live source coverage"]
          : [
              "No-key baseline uses only locally available adapters until network providers are enabled",
            ],
      },
      provenance: {
        artifactIds: artifacts.map((artifact) => artifact.id),
        observedClaims: claims.length,
      },
    });
    database.saveSnapshot(runId, snapshot);
    await emit("WORLD SYNTHESIS", "snapshot.created", "Target-centred world snapshot persisted", {
      metadata: { snapshotId: snapshot.id },
    });
    database.updateRunPhase(runId, "live");
    await emit("LIVE WATCH", "world.live", "World construction complete · live tracking active");
  } catch (error) {
    database.updateRunPhase(runId, "failed", (error as Error).message);
    await emit(
      "WORLD SYNTHESIS",
      "world.failed",
      `World construction failed: ${(error as Error).message}`,
      { status: "failed" },
    );
    throw error;
  }
}
