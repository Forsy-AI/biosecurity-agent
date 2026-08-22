import { startServer } from "./app.js";
import { hostname } from "node:os";
import { promises as dns } from "node:dns";

const args = new Set(process.argv.slice(2));
const portIndex = process.argv.indexOf("--port");
const port =
  portIndex >= 0 ? Number(process.argv[portIndex + 1]) : Number(process.env.PORT ?? 7331);

let bindHost = "127.0.0.1";
if (process.env.BIOSECURITY_DOCKER_BIND === "true") {
  bindHost = (await dns.lookup(hostname(), { family: 4 })).address;
  process.env.BIOSECURITY_BOUND_HOST = bindHost;
}
if (bindHost === "0.0.0.0" || bindHost === "::")
  throw new Error("Wildcard HTTP binds are prohibited");

const app = await startServer({
  port,
  host: bindHost,
  logger: !args.has("--quiet"),
  serveWeb: !args.has("--dev-api-only"),
});

const close = async (): Promise<void> => {
  await app.close();
  process.exit(0);
};
process.once("SIGINT", () => void close());
process.once("SIGTERM", () => void close());
