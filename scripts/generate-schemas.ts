import { mkdir, writeFile } from "node:fs/promises";
import { zodToJsonSchema } from "zod-to-json-schema";
import {
  AgentConfigSchema,
  ClaimSchema,
  ProcessingEventSchema,
  SimulationPlanSchema,
  SourceArtifactSchema,
  TargetSchema,
  WorldSnapshotSchema,
} from "../packages/contracts/src/index.js";

const schemas = {
  Target: TargetSchema,
  SourceArtifact: SourceArtifactSchema,
  Claim: ClaimSchema,
  WorldSnapshot: WorldSnapshotSchema,
  ProcessingEvent: ProcessingEventSchema,
  AgentConfig: AgentConfigSchema,
  SimulationPlan: SimulationPlanSchema,
};

await mkdir("packages/contracts/generated", { recursive: true });
for (const [name, schema] of Object.entries(schemas)) {
  await writeFile(
    `packages/contracts/generated/${name}.schema.json`,
    `${JSON.stringify(zodToJsonSchema(schema, name), null, 2)}\n`,
    "utf8",
  );
}
