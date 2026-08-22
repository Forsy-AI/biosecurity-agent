import { createHash } from "node:crypto";
import { Readability } from "@mozilla/readability";
import { parseHTML } from "linkedom";
import { XMLParser } from "fast-xml-parser";
import pdfParse from "pdf-parse/lib/pdf-parse.js";
import { nanoid } from "nanoid";
import {
  SourceArtifactSchema,
  type SourceArtifact,
  type SourceManifest,
} from "@biosecurity/contracts";
import {
  MAX_REDIRECTS,
  MAX_SOURCE_BYTES,
  isolateHtml,
  isolateText,
  validateRemoteUrl,
  type IsolatedContent,
} from "@biosecurity/safety";

type DiscoveryQuery = {
  query: string;
  language?: string;
  geography?: string;
  cursor?: string;
  limit?: number;
};

type DiscoveredSource = {
  providerId: string;
  url: string;
  title?: string;
  publishedAt?: string;
  metadata: Record<string, unknown>;
};

type RetrievalRequest = {
  url: string;
  allowPrivateNetwork?: boolean;
  expectedType?: string;
};
type RetrievedArtifact = {
  artifact: SourceArtifact;
  isolated: IsolatedContent;
  bytes: number;
};
interface DiscoveryProvider {
  readonly manifest: SourceManifest;
  discover(query: DiscoveryQuery): Promise<DiscoveredSource[]>;
}

interface RetrievalProvider {
  readonly manifest: SourceManifest;
  supports(url: URL, contentType?: string): boolean;
  retrieve(request: RetrievalRequest): Promise<RetrievedArtifact>;
}

interface CustomSourceProvider {
  readonly manifest: SourceManifest;
  validate(configuration: unknown): Promise<{ valid: boolean; errors: string[] }>;
  poll(
    configuration: unknown,
    cursor?: string,
  ): Promise<{ sources: DiscoveredSource[]; cursor?: string }>;
}

export function normalizeExternalPublishedAt(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) return undefined;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return undefined;
  const year = parsed.getUTCFullYear();
  if (year < 0 || year > 9999) return undefined;
  return parsed.toISOString();
}

export class SafeHttpClient {
  async fetch(
    input: string,
    options: { allowPrivateNetwork?: boolean; timeoutMs?: number; accept?: string } = {},
  ): Promise<{ response: Response; body: Buffer; finalUrl: string }> {
    let current = await validateRemoteUrl(input, {
      allowPrivateNetwork: options.allowPrivateNetwork,
    });
    for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
      const response = await fetch(current, {
        redirect: "manual",
        headers: {
          accept:
            options.accept ??
            "text/html,application/xhtml+xml,application/json,application/pdf,text/plain;q=0.8,*/*;q=0.2",
          "user-agent": "BiosecurityAgent/0.1 (+local defensive OSINT; respects source controls)",
        },
        signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
      });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) throw new Error("Redirect response did not include a location");
        current = await validateRemoteUrl(new URL(location, current).toString(), {
          allowPrivateNetwork: options.allowPrivateNetwork,
        });
        continue;
      }
      if (!response.ok) throw new Error(`Source returned HTTP ${response.status}`);
      const declared = Number(response.headers.get("content-length") ?? 0);
      if (declared > MAX_SOURCE_BYTES) throw new Error("Source exceeds the retrieval size limit");
      const reader = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let received = 0;
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          received += value.byteLength;
          if (received > MAX_SOURCE_BYTES) {
            await reader.cancel();
            throw new Error("Source exceeded the retrieval size limit while streaming");
          }
          chunks.push(value);
        }
      }
      return { response, body: Buffer.concat(chunks), finalUrl: current.toString() };
    }
    throw new Error(`Source exceeded the ${MAX_REDIRECTS} redirect limit`);
  }
}

const basicManifest = (
  partial: Partial<SourceManifest> &
    Pick<SourceManifest, "id" | "name" | "sourceClass" | "accessMethod">,
): SourceManifest => ({
  id: partial.id,
  name: partial.name,
  sourceClass: partial.sourceClass,
  geographicCoverage: partial.geographicCoverage ?? ["global"],
  languages: partial.languages ?? ["multiple"],
  dataEventTypes: partial.dataEventTypes ?? ["documents"],
  accessMethod: partial.accessMethod,
  authenticationRequirements: partial.authenticationRequirements ?? "none",
  cadence: partial.cadence ?? "on demand",
  typicalDelay: partial.typicalDelay ?? "source dependent",
  licence: partial.licence ?? "source-specific",
  redistributionPermission: partial.redistributionPermission ?? "metadata and lawful excerpts only",
  commercialUseStatus: partial.commercialUseStatus ?? "verify source terms",
  knownLimitations: partial.knownLimitations ?? [],
  health: partial.health ?? "available",
});

function artifactFrom(
  providerId: string,
  sourceClass: SourceArtifact["sourceClass"],
  url: string,
  isolated: IsolatedContent,
  metadata: {
    title?: string;
    language?: string;
    publishedAt?: string;
    licence?: string;
    redistribution?: string;
  } = {},
): SourceArtifact {
  const now = new Date().toISOString();
  const publishedAt = normalizeExternalPublishedAt(metadata.publishedAt);
  return SourceArtifactSchema.parse({
    id: `artifact_${nanoid(12)}`,
    providerId,
    sourceClass,
    url,
    ...(metadata.title ? { title: metadata.title } : {}),
    ...(metadata.language ? { language: metadata.language } : {}),
    ...(publishedAt ? { publishedAt } : {}),
    retrievedAt: now,
    contentHash: isolated.contentHash,
    rawStorageRef: `sha256:${isolated.contentHash}`,
    ...(metadata.licence ? { licence: metadata.licence } : {}),
    ...(metadata.redistribution ? { redistribution: metadata.redistribution } : {}),
    trustMetadata: { untrusted: true, findings: isolated.findings, ...isolated.metadata },
    securityState: isolated.securityState,
  });
}

export class DirectHttpRetrievalProvider implements RetrievalProvider {
  readonly manifest = basicManifest({
    id: "direct-http",
    name: "Direct HTTP",
    sourceClass: "custom",
    accessMethod: "HTTP(S)",
  });
  readonly client = new SafeHttpClient();
  supports(url: URL): boolean {
    return url.protocol === "http:" || url.protocol === "https:";
  }
  async retrieve(request: RetrievalRequest): Promise<RetrievedArtifact> {
    const { response, body, finalUrl } = await this.client.fetch(request.url, {
      allowPrivateNetwork: request.allowPrivateNetwork,
    });
    const contentType =
      response.headers.get("content-type")?.split(";")[0]?.trim() ?? "application/octet-stream";
    let isolated: IsolatedContent;
    if (contentType.includes("html")) isolated = isolateHtml(body.toString("utf8"));
    else if (contentType === "application/pdf")
      isolated = isolateText((await pdfParse(body)).text, { parser: "pdf-parse" });
    else if (contentType.includes("json") || contentType.startsWith("text/"))
      isolated = isolateText(body.toString("utf8"));
    else throw new Error(`Unsupported source content type: ${contentType}`);
    const title = response.headers.get("x-source-title") ?? new URL(finalUrl).hostname;
    return {
      artifact: artifactFrom(this.manifest.id, this.manifest.sourceClass, finalUrl, isolated, {
        title,
      }),
      isolated,
      bytes: body.byteLength,
    };
  }
}

export class HtmlReadabilityRetrievalProvider extends DirectHttpRetrievalProvider {
  override readonly manifest = basicManifest({
    id: "html-readability",
    name: "Readable web documents",
    sourceClass: "news",
    accessMethod: "HTTP HTML",
  });
  override async retrieve(request: RetrievalRequest): Promise<RetrievedArtifact> {
    const { response, body, finalUrl } = await this.client.fetch(request.url, {
      allowPrivateNetwork: request.allowPrivateNetwork,
      accept: "text/html",
    });
    const html = body.toString("utf8");
    const security = isolateHtml(html);
    const { document } = parseHTML(html);
    const article = new Readability(document as unknown as Document).parse();
    const isolated = isolateText(article?.textContent ?? security.text, {
      parser: "readability",
      securityFindings: security.findings,
    });
    if (security.securityState === "quarantined") {
      isolated.securityState = "quarantined";
      isolated.findings.push(...security.findings);
    }
    return {
      artifact: artifactFrom(this.manifest.id, this.manifest.sourceClass, finalUrl, isolated, {
        title:
          article?.title ?? response.headers.get("x-source-title") ?? new URL(finalUrl).hostname,
        language: document.documentElement.lang || undefined,
      }),
      isolated,
      bytes: body.byteLength,
    };
  }
}

export class PlaywrightRetrievalProvider implements RetrievalProvider {
  readonly manifest = basicManifest({
    id: "playwright-web",
    name: "JavaScript web retrieval",
    sourceClass: "news",
    accessMethod: "headless browser",
    knownLimitations: ["Feature requires a locally installed Playwright Chromium browser"],
  });
  supports(url: URL): boolean {
    return ["http:", "https:"].includes(url.protocol);
  }
  async retrieve(request: RetrievalRequest): Promise<RetrievedArtifact> {
    const url = await validateRemoteUrl(request.url, {
      allowPrivateNetwork: request.allowPrivateNetwork,
    });
    const { chromium } = await import("playwright");
    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext({ javaScriptEnabled: true });
      const page = await context.newPage();
      await page.goto(url.toString(), { waitUntil: "domcontentloaded", timeout: 20_000 });
      const html = await page.content();
      const isolated = isolateHtml(html);
      return {
        artifact: artifactFrom(this.manifest.id, this.manifest.sourceClass, page.url(), isolated, {
          title: await page.title(),
        }),
        isolated,
        bytes: Buffer.byteLength(html),
      };
    } finally {
      await browser.close();
    }
  }
}

export class RssAtomDiscoveryProvider implements DiscoveryProvider, CustomSourceProvider {
  readonly manifest = basicManifest({
    id: "rss-atom",
    name: "RSS and Atom feeds",
    sourceClass: "custom",
    accessMethod: "RSS/Atom",
  });
  readonly client = new SafeHttpClient();
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const { body } = await this.client.fetch(query.query);
    const parsed = new XMLParser({ ignoreAttributes: false }).parse(body.toString("utf8")) as any;
    const items = parsed.rss?.channel?.item ?? parsed.feed?.entry ?? [];
    const list = Array.isArray(items) ? items : [items];
    return list.slice(0, query.limit ?? 50).flatMap((item: any) => {
      const url = typeof item.link === "string" ? item.link : (item.link?.["@_href"] ?? item.guid);
      if (!url) return [];
      const published = item.pubDate ?? item.published ?? item.updated;
      return [
        {
          providerId: this.manifest.id,
          url,
          ...(item.title
            ? { title: typeof item.title === "string" ? item.title : item.title["#text"] }
            : {}),
          ...(published && !Number.isNaN(Date.parse(published))
            ? { publishedAt: new Date(published).toISOString() }
            : {}),
          metadata: { untrusted: true },
        },
      ];
    });
  }
  async validate(configuration: unknown): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const value = String((configuration as any)?.url ?? "");
      await validateRemoteUrl(value);
      return { valid: true, errors: [] };
    } catch (error) {
      return { valid: false, errors: [(error as Error).message] };
    }
  }
  async poll(configuration: unknown): Promise<{ sources: DiscoveredSource[]; cursor?: string }> {
    const sources = await this.discover({ query: String((configuration as any).url) });
    return { sources, cursor: sources[0]?.publishedAt ?? new Date().toISOString() };
  }
}

export class XmlSitemapDiscoveryProvider implements DiscoveryProvider {
  readonly manifest = basicManifest({
    id: "xml-sitemap",
    name: "XML sitemaps",
    sourceClass: "custom",
    accessMethod: "XML sitemap",
  });
  readonly client = new SafeHttpClient();
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const { body } = await this.client.fetch(query.query);
    const parsed = new XMLParser().parse(body.toString("utf8")) as any;
    const entries = parsed.urlset?.url ?? parsed.sitemapindex?.sitemap ?? [];
    return (Array.isArray(entries) ? entries : [entries])
      .slice(0, query.limit ?? 100)
      .flatMap((entry: any) =>
        entry.loc
          ? [
              {
                providerId: this.manifest.id,
                url: String(entry.loc),
                metadata: { lastModified: entry.lastmod, untrusted: true },
              },
            ]
          : [],
      );
  }
}

export class JsonSearchDiscoveryProvider implements DiscoveryProvider {
  manifest: SourceManifest;
  readonly endpoint: string;
  readonly resultPath: string;
  readonly allowPrivateNetwork: boolean;
  constructor(
    endpoint: string,
    resultPath = "results",
    id = "generic-json-search",
    allowPrivateNetwork = false,
  ) {
    this.endpoint = endpoint;
    this.resultPath = resultPath;
    this.allowPrivateNetwork = allowPrivateNetwork;
    this.manifest = basicManifest({
      id,
      name: "Generic JSON search",
      sourceClass: "news",
      accessMethod: "JSON HTTP API",
    });
  }
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const endpoint = new URL(this.endpoint);
    endpoint.searchParams.set("q", query.query);
    if (query.language) endpoint.searchParams.set("language", query.language);
    const { body } = await new SafeHttpClient().fetch(endpoint.toString(), {
      allowPrivateNetwork: this.allowPrivateNetwork,
    });
    const payload = JSON.parse(body.toString("utf8")) as any;
    const items = this.resultPath.split(".").reduce((value, key) => value?.[key], payload);
    if (!Array.isArray(items))
      throw new Error("Search response mapping did not resolve to an array");
    return items.slice(0, query.limit ?? 25).flatMap((item) =>
      item.url
        ? [
            {
              providerId: this.manifest.id,
              url: String(item.url),
              ...(item.title ? { title: String(item.title) } : {}),
              metadata: { untrusted: true },
            },
          ]
        : [],
    );
  }
}

export class SearXNGDiscoveryProvider extends JsonSearchDiscoveryProvider {
  constructor(endpoint?: string) {
    const configuredEndpoint = endpoint ?? process.env.BIOSECURITY_SEARXNG_URL;
    const selectedEndpoint = configuredEndpoint ?? "http://127.0.0.1:8080";
    super(
      `${selectedEndpoint.replace(/\/$/, "")}/search?format=json`,
      "results",
      "searxng",
      Boolean(configuredEndpoint),
    );
    this.manifest = basicManifest({
      id: "searxng",
      name: "Local SearXNG",
      sourceClass: "news",
      accessMethod: "self-hosted JSON search API",
      knownLimitations: ["Disabled until a local SearXNG endpoint is configured"],
      health: configuredEndpoint ? "available" : "unconfigured",
    });
  }
}

export class GdeltDiscoveryProvider extends JsonSearchDiscoveryProvider {
  constructor() {
    super(
      "https://api.gdeltproject.org/api/v2/doc/doc?format=json&mode=artlist&maxrecords=25",
      "articles",
      "gdelt",
    );
    this.manifest = basicManifest({
      id: "gdelt",
      name: "GDELT DOC 2.0",
      sourceClass: "news",
      accessMethod: "public JSON API",
      cadence: "near-real time",
      licence: "GDELT terms",
      knownLimitations: ["Discovery metadata requires independent retrieval and verification"],
    });
  }

  override async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const endpoint = new URL("https://api.gdeltproject.org/api/v2/doc/doc");
    endpoint.searchParams.set("query", query.query);
    endpoint.searchParams.set("format", "json");
    endpoint.searchParams.set("mode", "artlist");
    endpoint.searchParams.set("maxrecords", String(Math.min(query.limit ?? 25, 250)));
    const { body } = await new SafeHttpClient().fetch(endpoint.toString());
    const payload = JSON.parse(body.toString("utf8")) as any;
    return (payload.articles ?? []).flatMap((item: any) =>
      item.url
        ? [
            {
              providerId: this.manifest.id,
              url: String(item.url),
              ...(item.title ? { title: String(item.title) } : {}),
              ...(item.seendate && !Number.isNaN(Date.parse(item.seendate))
                ? { publishedAt: new Date(item.seendate).toISOString() }
                : {}),
              metadata: {
                domain: item.domain,
                language: item.language,
                sourceCountry: item.sourcecountry,
                untrusted: true,
              },
            },
          ]
        : [],
    );
  }
}

export class CommonCrawlDiscoveryProvider implements DiscoveryProvider {
  readonly manifest = basicManifest({
    id: "common-crawl",
    name: "Common Crawl index",
    sourceClass: "news",
    accessMethod: "public CDX index",
    cadence: "crawl release",
    licence: "source content retains original rights",
    knownLimitations: ["Archive coverage and freshness vary"],
  });
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const client = new SafeHttpClient();
    const { body: collectionsBody } = await client.fetch(
      "https://index.commoncrawl.org/collinfo.json",
      { accept: "application/json" },
    );
    const collections = JSON.parse(collectionsBody.toString("utf8")) as Array<{
      "cdx-api"?: unknown;
    }>;
    const currentIndex = collections.find((item) => typeof item["cdx-api"] === "string")?.[
      "cdx-api"
    ];
    if (typeof currentIndex !== "string")
      throw new Error("Common Crawl did not publish a current CDX index endpoint");
    const endpoint = new URL(currentIndex);
    endpoint.searchParams.set("url", query.query);
    endpoint.searchParams.set("output", "json");
    endpoint.searchParams.set("filter", "status:200");
    endpoint.searchParams.set("collapse", "digest");
    let body: Buffer;
    try {
      ({ body } = await client.fetch(endpoint.toString()));
    } catch (error) {
      if ((error as Error).message === "Source returned HTTP 404") return [];
      throw error;
    }
    return body
      .toString("utf8")
      .split("\n")
      .filter(Boolean)
      .slice(0, query.limit ?? 20)
      .map((line) => JSON.parse(line) as any)
      .map((item) => ({
        providerId: this.manifest.id,
        url: item.url,
        metadata: { timestamp: item.timestamp, archive: true, untrusted: true },
      }));
  }
}

export class BlueskyPublicDiscoveryProvider implements DiscoveryProvider {
  readonly manifest = basicManifest({
    id: "bluesky-public",
    name: "Bluesky public search",
    sourceClass: "social",
    accessMethod: "public AppView API",
    typicalDelay: "near-real time",
    knownLimitations: ["Public posts are leads, not authoritative evidence"],
  });
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    const endpoint = new URL("https://api.bsky.app/xrpc/app.bsky.feed.searchPosts");
    endpoint.searchParams.set("q", query.query);
    endpoint.searchParams.set("limit", String(Math.min(query.limit ?? 25, 100)));
    const { body } = await new SafeHttpClient().fetch(endpoint.toString());
    const payload = JSON.parse(body.toString("utf8")) as any;
    return (payload.posts ?? []).map((post: any) => {
      const publishedAt = normalizeExternalPublishedAt(post.record?.createdAt);
      return {
        providerId: this.manifest.id,
        url: `https://bsky.app/profile/${post.author.handle}/post/${String(post.uri).split("/").at(-1)}`,
        title: `Public post by ${post.author.displayName || post.author.handle}`,
        ...(publishedAt ? { publishedAt } : {}),
        metadata: { cid: post.cid, text: post.record?.text, untrusted: true },
      };
    });
  }
}

export class MastodonPublicDiscoveryProvider implements DiscoveryProvider {
  readonly manifest = basicManifest({
    id: "mastodon-public",
    name: "Mastodon public hashtag search",
    sourceClass: "social",
    accessMethod: "instance public API",
    knownLimitations: [
      "Availability and policy vary by instance",
      "Requires an explicitly configured instance",
    ],
    health: "unconfigured",
  });
  readonly instance?: string;
  constructor(instance?: string) {
    this.instance = instance;
  }
  async discover(query: DiscoveryQuery): Promise<DiscoveredSource[]> {
    if (!this.instance) throw new Error("A Mastodon instance must be configured");
    const tag = query.query.replace(/^#/, "").replace(/[^\p{L}\p{N}_-]/gu, "");
    const endpoint = new URL(`/api/v1/timelines/tag/${tag}`, this.instance);
    const { body } = await new SafeHttpClient().fetch(endpoint.toString());
    return (JSON.parse(body.toString("utf8")) as any[]).map((post) => {
      const publishedAt = normalizeExternalPublishedAt(post.created_at);
      return {
        providerId: this.manifest.id,
        url: post.url,
        ...(publishedAt ? { publishedAt } : {}),
        metadata: { content: post.content, untrusted: true },
      };
    });
  }
}

export function normalizedContentHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
