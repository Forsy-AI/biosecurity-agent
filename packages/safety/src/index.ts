import { createHash } from "node:crypto";
import { promises as dns } from "node:dns";
import { isIP } from "node:net";
import { extname, normalize, resolve, sep } from "node:path";
import * as cheerio from "cheerio";

export const MAX_SOURCE_BYTES = 5 * 1024 * 1024;
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
export const MAX_REDIRECTS = 3;

const PRIVATE_V4 = [
  /^10\./,
  /^127\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions?/i,
  /system\s+prompt/i,
  /developer\s+message/i,
  /send\s+(me\s+)?(all\s+)?(secrets?|tokens?|api\s*keys?)/i,
  /exfiltrat(?:e|ion)/i,
  /execute\s+(this\s+)?(?:tool|command|shell)/i,
  /do\s+not\s+tell\s+the\s+user/i,
  /(?:调用|執行).{0,16}(?:工具|命令)/u,
  /(?:ignora|ignorez).{0,30}(?:instrucciones|instructions)/i,
];

const DISALLOWED_BIO_PATTERNS = [
  /optim(?:ize|ise|ization).{0,50}(?:virulence|transmissibility|immune.?evasion|mutation)/i,
  /design.{0,50}(?:pathogen|viral genome|bacterial strain).{0,40}(?:more|increased|enhanced)/i,
  /step.?by.?step.{0,60}(?:synthesi[sz]e|cultivat|weaponiz)/i,
  /(?:gene|sequence).{0,40}(?:edit|modify).{0,40}(?:virulence|transmissibility|immune)/i,
];

const MEDICAL_OVERCLAIM_PATTERNS = [
  /you (?:definitely|certainly) have/i,
  /diagnos(?:e|is):/i,
  /take \d+(?:\.\d+)?\s*(?:mg|ml)/i,
];

export type SecurityFinding = {
  code: string;
  severity: "low" | "medium" | "high";
  message: string;
};

export type IsolatedContent = {
  label: "UNTRUSTED_SOURCE_CONTENT";
  text: string;
  contentHash: string;
  findings: SecurityFinding[];
  securityState: "accepted" | "quarantined" | "rejected";
  metadata: Record<string, unknown>;
};

export function isPrivateAddress(address: string): boolean {
  if (address === "::" || address === "::1" || address.toLowerCase().startsWith("fe80:"))
    return true;
  if (address.toLowerCase().startsWith("fc") || address.toLowerCase().startsWith("fd")) return true;
  if (address.startsWith("::ffff:")) return isPrivateAddress(address.slice(7));
  return PRIVATE_V4.some((pattern) => pattern.test(address));
}

export async function validateRemoteUrl(
  value: string,
  options: { allowPrivateNetwork?: boolean; protocols?: string[] } = {},
): Promise<URL> {
  const url = new URL(value);
  const protocols = options.protocols ?? ["http:", "https:"];
  if (!protocols.includes(url.protocol)) throw new Error(`Protocol ${url.protocol} is not allowed`);
  if (url.username || url.password) throw new Error("Credentials in source URLs are not allowed");
  if (url.hostname === "localhost" || url.hostname.endsWith(".localhost")) {
    if (!options.allowPrivateNetwork)
      throw new Error("Private-network sources are blocked by default");
    return url;
  }
  const directIp = isIP(url.hostname) ? [url.hostname] : [];
  const addresses =
    directIp.length > 0
      ? directIp
      : (await dns.lookup(url.hostname, { all: true })).map((entry) => entry.address);
  if (!options.allowPrivateNetwork && addresses.some(isPrivateAddress)) {
    throw new Error("Private-network sources are blocked by default");
  }
  return url;
}

export function validateUpload(
  filename: string,
  mediaType: string,
  size: number,
): { extension: string; mediaType: string } {
  if (size > MAX_UPLOAD_BYTES) throw new Error(`Upload exceeds ${MAX_UPLOAD_BYTES} bytes`);
  const extension = extname(filename).toLowerCase();
  const allowedExtensions = new Set([
    ".pdf",
    ".md",
    ".txt",
    ".csv",
    ".json",
    ".html",
    ".htm",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
  ]);
  const allowedTypes = ["application/pdf", "text/", "application/json", "image/"];
  if (!allowedExtensions.has(extension)) throw new Error("Unsupported upload type");
  if (!allowedTypes.some((prefix) => mediaType.startsWith(prefix)))
    throw new Error("Content type does not match an allowed upload class");
  return { extension, mediaType };
}

export function safeUploadPath(baseDir: string, filename: string): string {
  const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_").replace(/^\.+/, "");
  if (!safeName) throw new Error("Invalid filename");
  const base = resolve(baseDir);
  const candidate = resolve(base, normalize(safeName));
  if (candidate !== base && !candidate.startsWith(`${base}${sep}`))
    throw new Error("Path traversal blocked");
  return candidate;
}

export function scanPromptInjection(text: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        code: "prompt-injection",
        severity: "high",
        message: "Source-derived tool or instruction language was detected.",
      });
      break;
    }
  }
  return findings;
}

export function isolateHtml(html: string): IsolatedContent {
  const limited = html.slice(0, MAX_SOURCE_BYTES);
  const $ = cheerio.load(limited);
  const findings = scanPromptInjection(limited);
  const hidden = $(
    "[hidden], [aria-hidden='true'], [style*='display:none'], [style*='display: none'], [style*='visibility:hidden'], [style*='font-size:0']",
  )
    .text()
    .trim();
  if (hidden) {
    findings.push({
      code: "hidden-text",
      severity: "medium",
      message: "Hidden source text was removed.",
    });
  }
  $(
    "script, style, noscript, template, iframe, object, embed, [hidden], [aria-hidden='true']",
  ).remove();
  const text = $("body").text().replace(/\s+/g, " ").trim().slice(0, MAX_SOURCE_BYTES);
  return finalizeIsolation(text, findings, {
    originalBytes: Buffer.byteLength(html),
    truncated: html.length > limited.length,
  });
}

export function isolateText(text: string, metadata: Record<string, unknown> = {}): IsolatedContent {
  const limited = text.slice(0, MAX_SOURCE_BYTES);
  // eslint-disable-next-line no-control-regex -- control characters are stripped from untrusted source data.
  const sanitized = limited.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "");
  return finalizeIsolation(sanitized, scanPromptInjection(limited), {
    ...metadata,
    originalBytes: Buffer.byteLength(text),
    truncated: text.length > limited.length,
  });
}

function finalizeIsolation(
  text: string,
  findings: SecurityFinding[],
  metadata: Record<string, unknown>,
): IsolatedContent {
  const securityState = findings.some((finding) => finding.severity === "high")
    ? "quarantined"
    : "accepted";
  return {
    label: "UNTRUSTED_SOURCE_CONTENT",
    text,
    contentHash: createHash("sha256").update(text).digest("hex"),
    findings,
    securityState,
    metadata,
  };
}

export function validateDefensiveRequest(text: string): void {
  if (DISALLOWED_BIO_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new Error("Request rejected: disallowed biological enablement");
  }
}

export function validateAgentOutput(
  output: { text?: string; evidenceIds?: string[]; factual?: boolean },
  knownEvidenceIds: Set<string>,
): void {
  const text = output.text ?? "";
  if (DISALLOWED_BIO_PATTERNS.some((pattern) => pattern.test(text)))
    throw new Error("Agent output contains disallowed biological enablement");
  if (MEDICAL_OVERCLAIM_PATTERNS.some((pattern) => pattern.test(text)))
    throw new Error("Agent output contains unsupported clinical language");
  if (output.factual && (!output.evidenceIds || output.evidenceIds.length === 0))
    throw new Error("Factual biosecurity output requires evidence IDs");
  if (output.evidenceIds?.some((id) => !knownEvidenceIds.has(id)))
    throw new Error("Agent output referenced unknown evidence");
}

export function validateSimulationSafety(planText: string): void {
  validateDefensiveRequest(planText);
  if (/wet.?lab|synthesis protocol|cultivation parameters/i.test(planText)) {
    throw new Error("Simulation plans must remain abstract and defensive");
  }
}

export class SecretRedactor {
  readonly #secrets = new Set<string>();

  register(value: string | undefined): void {
    if (value && value.length >= 6) this.#secrets.add(value);
  }

  redact(value: unknown): unknown {
    if (typeof value === "string") {
      let redacted = value;
      for (const secret of this.#secrets) redacted = redacted.replaceAll(secret, "[REDACTED]");
      redacted = redacted.replace(
        /(?:sk-[A-Za-z0-9_-]{12,}|Bearer\s+[A-Za-z0-9._~-]{12,})/g,
        "[REDACTED]",
      );
      return redacted;
    }
    if (Array.isArray(value)) return value.map((entry) => this.redact(entry));
    if (value && typeof value === "object") {
      return Object.fromEntries(
        Object.entries(value).map(([key, entry]) => [
          key,
          /api.?key|token|authorization|secret|password/i.test(key)
            ? "[REDACTED]"
            : this.redact(entry),
        ]),
      );
    }
    return value;
  }
}

export const toolInstructionBoundary = (content: IsolatedContent): string =>
  `<untrusted-source security-state="${content.securityState}">\n${content.text}\n</untrusted-source>`;
