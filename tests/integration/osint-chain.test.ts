import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ClaimSchema, SourceArtifactSchema, type Claim } from "@biosecurity/contracts";
import {
  DirectHttpRetrievalProvider,
  SearXNGDiscoveryProvider,
} from "../../apps/server/src/local/public-sources.js";
import { modelTargets } from "../../apps/server/src/local/targeting.js";
import {
  deduplicateArtifacts,
  estimateCorroboration,
  targetRelevance,
} from "../../apps/server/src/local/world.js";

describe("generic OSINT chain", () => {
  const server = createServer((request, response) => {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    if (request.url?.startsWith("/search")) {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          results: [
            { url: `${base}/report-a`, title: "Independent tomato plant advisory" },
            { url: `${base}/report-b`, title: "Second tomato plant advisory" },
            { url: `${base}/report-duplicate`, title: "Syndicated advisory" },
          ],
        }),
      );
      return;
    }
    response.setHeader("content-type", "text/html; charset=utf-8");
    if (request.url === "/report-b") {
      response.end(
        "<html><body><article>Tomato plants in Kent have a new official monitoring advisory.</article></body></html>",
      );
      return;
    }
    response.end(
      "<html><script>window.decorative = true</script><body><article>Tomato plants in Kent have an official monitoring advisory.</article></body></html>",
    );
  });
  let baseUrl = "";

  beforeAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("discovers, retrieves, isolates, structures, deduplicates, corroborates, and links", async () => {
    const discovered = await new SearXNGDiscoveryProvider(baseUrl).discover({
      query: "tomato plant health Kent",
      limit: 3,
    });
    expect(discovered).toHaveLength(3);

    const retriever = new DirectHttpRetrievalProvider();
    const retrieved = await Promise.all(
      discovered.map((source) =>
        retriever.retrieve({ url: source.url, allowPrivateNetwork: true }),
      ),
    );
    expect(retrieved.every((item) => item.isolated.label === "UNTRUSTED_SOURCE_CONTENT")).toBe(
      true,
    );
    expect(retrieved[0]!.isolated.text).not.toContain("window.decorative");

    const artifacts = retrieved.map((item, index) =>
      SourceArtifactSchema.parse({ ...item.artifact, providerId: `ordinary-source-${index}` }),
    );
    const claims: Claim[] = artifacts.map((artifact, index) =>
      ClaimSchema.parse({
        id: `claim-osint-${index}`,
        artifactId: artifact.id,
        subject: { id: "entity-tomatoes", label: "Kent tomato plants", kind: "plant" },
        predicate: "monitoring-advisory",
        object: "active",
        evidenceSpan: { excerpt: retrieved[index]!.isolated.text },
        confidence: 0.5,
        state: "observed",
      }),
    );
    const duplicateClusters = deduplicateArtifacts(artifacts).filter(
      (cluster) => cluster.duplicates.length > 0,
    );
    expect(duplicateClusters).toHaveLength(1);
    expect(estimateCorroboration(claims[0]!, claims, artifacts)).toBeGreaterThan(0.5);

    const [target] = modelTargets([
      { name: "Tomato plants", description: "Tomato plants in Kent" },
    ]);
    expect(targetRelevance(target!, claims[0]!)).toBeGreaterThan(0.3);
  });
});
