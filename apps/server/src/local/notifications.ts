import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { nanoid } from "nanoid";
import nodemailer from "nodemailer";
import {
  AgentNotificationSchema,
  NotificationDeliverySchema,
  NotificationDestinationInputSchema,
  NotificationDestinationSchema,
  ProcessingEventSchema,
  type AgentNotification,
  type NotificationDelivery,
  type NotificationDestination,
  type NotificationDestinationInput,
  type Target,
  type WorldSnapshot,
} from "@biosecurity/contracts";
import type { AgentAdapter } from "@biosecurity/agent-adapters";
import {
  SecretRedactor,
  isolateText,
  validateAgentOutput,
  validateRemoteUrl,
} from "@biosecurity/safety";
import type { BiosecurityDatabase, SecretStore } from "./state.js";

export type NotificationTestResult = { ok: boolean; message: string };
export type NotificationSendResult = {
  ok: boolean;
  providerMessageId?: string;
  errorCode?: string;
  message: string;
};

export interface NotificationChannel {
  readonly id: string;
  readonly type: NotificationDestination["type"];
  readonly name: string;
  test(): Promise<NotificationTestResult>;
  send(notification: AgentNotification): Promise<NotificationSendResult>;
}

type NotificationDecision = { notify: boolean; title?: string; summary?: string; reason?: string };

const secretKey = (destinationId: string, field: string): string =>
  `notification:${destinationId}:${field}`;

export class MockNotificationChannel implements NotificationChannel {
  readonly type = "mock" as const;
  readonly id: string;
  readonly name: string;
  readonly deliveries: AgentNotification[];
  constructor(destination: NotificationDestination, deliveries: AgentNotification[] = []) {
    this.id = destination.id;
    this.name = destination.name;
    this.deliveries = deliveries;
  }
  async test(): Promise<NotificationTestResult> {
    return { ok: true, message: "Local mock notification channel ready" };
  }
  async send(notification: AgentNotification): Promise<NotificationSendResult> {
    this.deliveries.push(notification);
    return {
      ok: true,
      providerMessageId: `mock_${nanoid(8)}`,
      message: "Delivered to local mock channel",
    };
  }
}

export class SmtpNotificationChannel implements NotificationChannel {
  readonly type = "smtp" as const;
  readonly id: string;
  readonly name: string;
  readonly destination: NotificationDestination;
  readonly secrets: SecretStore;
  constructor(destination: NotificationDestination, secrets: SecretStore) {
    this.id = destination.id;
    this.name = destination.name;
    this.destination = destination;
    this.secrets = secrets;
  }
  async #transport(): Promise<nodemailer.Transporter> {
    const host = await this.secrets.get(secretKey(this.id, "smtp-host"));
    const username = await this.secrets.get(secretKey(this.id, "smtp-username"));
    const password = await this.secrets.get(secretKey(this.id, "smtp-password"));
    if (!host) throw new Error("SMTP connection must be reconnected");
    await validateRemoteUrl(`smtp://${host}:${String(this.destination.settings.port)}`, {
      allowPrivateNetwork: this.destination.allowPrivateNetwork,
      protocols: ["smtp:", "smtps:"],
    });
    return nodemailer.createTransport({
      host,
      port: Number(this.destination.settings.port),
      secure: Boolean(this.destination.settings.secure),
      requireTLS: Boolean(this.destination.settings.requireTls),
      ...(username ? { auth: { user: username, pass: password ?? "" } } : {}),
      connectionTimeout: 8_000,
      greetingTimeout: 8_000,
      socketTimeout: 12_000,
    });
  }
  async test(): Promise<NotificationTestResult> {
    try {
      const transport = await this.#transport();
      await transport.verify();
      return { ok: true, message: "SMTP connection verified" };
    } catch (error) {
      return { ok: false, message: (error as Error).message };
    }
  }
  async send(notification: AgentNotification): Promise<NotificationSendResult> {
    try {
      const transport = await this.#transport();
      const result = await transport.sendMail({
        from: String(this.destination.settings.from),
        to: this.destination.destination,
        subject: `Biosecurity Agent · ${notification.title}`,
        text: formatNotification(notification),
      });
      return { ok: true, providerMessageId: result.messageId, message: "Email sent" };
    } catch (error) {
      return { ok: false, errorCode: "smtp-delivery-failed", message: (error as Error).message };
    }
  }
}

export class WebhookNotificationChannel implements NotificationChannel {
  readonly type = "webhook" as const;
  readonly id: string;
  readonly name: string;
  readonly destination: NotificationDestination;
  readonly secrets: SecretStore;
  constructor(destination: NotificationDestination, secrets: SecretStore) {
    this.id = destination.id;
    this.name = destination.name;
    this.destination = destination;
    this.secrets = secrets;
  }
  async #url(): Promise<URL> {
    const value = await this.secrets.get(secretKey(this.id, "webhook-url"));
    if (!value) throw new Error("Webhook connection must be reconnected");
    return validateRemoteUrl(value, { allowPrivateNetwork: this.destination.allowPrivateNetwork });
  }
  async test(): Promise<NotificationTestResult> {
    try {
      await this.#url();
      return { ok: true, message: "Webhook URL passed security validation" };
    } catch (error) {
      return { ok: false, message: (error as Error).message };
    }
  }
  async send(notification: AgentNotification): Promise<NotificationSendResult> {
    try {
      const url = await this.#url();
      const response = await fetch(url, {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/json", "user-agent": "BiosecurityAgent/0.1" },
        body: JSON.stringify({
          source: "Biosecurity Agent",
          notification,
          message: formatNotification(notification),
        }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}`);
      return { ok: true, message: "Webhook notification sent" };
    } catch (error) {
      return { ok: false, errorCode: "webhook-delivery-failed", message: (error as Error).message };
    }
  }
}

export class McpNotificationChannel implements NotificationChannel {
  readonly type = "mcp" as const;
  readonly id: string;
  readonly name: string;
  readonly destination: NotificationDestination;
  readonly secrets: SecretStore;
  constructor(destination: NotificationDestination, secrets: SecretStore) {
    this.id = destination.id;
    this.name = destination.name;
    this.destination = destination;
    this.secrets = secrets;
  }
  async #configuration(): Promise<{ url: URL; toolName: string; bearerToken?: string }> {
    const serverUrl = await this.secrets.get(secretKey(this.id, "mcp-server-url"));
    const toolName = await this.secrets.get(secretKey(this.id, "mcp-tool-name"));
    const bearerToken = await this.secrets.get(secretKey(this.id, "mcp-bearer-token"));
    if (!serverUrl || !toolName) throw new Error("MCP notification connection must be reconnected");
    return {
      url: await validateRemoteUrl(serverUrl, {
        allowPrivateNetwork: this.destination.allowPrivateNetwork,
      }),
      toolName,
      ...(bearerToken ? { bearerToken } : {}),
    };
  }
  async test(): Promise<NotificationTestResult> {
    try {
      await this.#configuration();
      return { ok: true, message: "MCP endpoint and notification tool scope validated" };
    } catch (error) {
      return { ok: false, message: (error as Error).message };
    }
  }
  async send(notification: AgentNotification): Promise<NotificationSendResult> {
    let client: Client | undefined;
    try {
      const config = await this.#configuration();
      client = new Client({ name: "biosecurity-agent-notifications", version: "0.1.0" });
      const transport = new StreamableHTTPClientTransport(config.url, {
        requestInit: config.bearerToken
          ? { headers: { authorization: `Bearer ${config.bearerToken}` } }
          : undefined,
      });
      await client.connect(transport);
      const tools = await client.listTools();
      if (!tools.tools.some((tool) => tool.name === config.toolName))
        throw new Error("Configured MCP notification tool is unavailable");
      await client.callTool({
        name: config.toolName,
        arguments: {
          notification,
          message: formatNotification(notification),
          scope: "biosecurity-agent-alert",
        },
      });
      return { ok: true, message: "MCP notification tool called" };
    } catch (error) {
      return { ok: false, errorCode: "mcp-delivery-failed", message: (error as Error).message };
    } finally {
      await client?.close().catch(() => undefined);
    }
  }
}

export function formatNotification(notification: AgentNotification): string {
  return [
    "Biosecurity Agent",
    "",
    notification.title,
    "",
    notification.summary,
    "",
    `Why: ${notification.reason}`,
    `Evidence records: ${notification.evidenceIds.length}`,
    `Updated: ${notification.createdAt}`,
    "",
    "Open Biosecurity Agent on the device where it is running to inspect the evidence.",
  ].join("\n");
}

export class NotificationService {
  readonly database: BiosecurityDatabase;
  readonly secrets: SecretStore;
  readonly redactor: SecretRedactor;
  readonly mockDeliveries: AgentNotification[] = [];
  readonly adapters = new Map<string, AgentAdapter>();

  constructor(
    database: BiosecurityDatabase,
    secrets: SecretStore,
    redactor = new SecretRedactor(),
  ) {
    this.database = database;
    this.secrets = secrets;
    this.redactor = redactor;
  }

  setAgent(runId: string, adapter: AgentAdapter): void {
    this.adapters.set(runId, adapter);
  }

  async createDestination(
    runId: string,
    raw: NotificationDestinationInput,
  ): Promise<NotificationDestination> {
    if (!this.database.getRun(runId)) throw new Error("Run not found");
    const input = NotificationDestinationInputSchema.parse(raw);
    const id = `destination_${nanoid(10)}`;
    const now = new Date().toISOString();
    const settings: Record<string, unknown> = {};
    if (input.type === "smtp") {
      if (!input.smtp) throw new Error("SMTP settings are required");
      await validateRemoteUrl(`smtp://${input.smtp.host}:${input.smtp.port}`, {
        allowPrivateNetwork: input.allowPrivateNetwork,
        protocols: ["smtp:", "smtps:"],
      });
      await this.secrets.set(secretKey(id, "smtp-host"), input.smtp.host);
      if (input.smtp.username)
        await this.secrets.set(secretKey(id, "smtp-username"), input.smtp.username);
      if (input.smtp.password) {
        this.redactor.register(input.smtp.password);
        await this.secrets.set(secretKey(id, "smtp-password"), input.smtp.password);
      }
      Object.assign(settings, {
        hostLabel: input.smtp.host,
        port: input.smtp.port,
        from: input.smtp.from,
        secure: input.smtp.secure,
        requireTls: input.smtp.requireTls,
        credentialsConfigured: Boolean(input.smtp.username || input.smtp.password),
      });
    } else if (input.type === "webhook") {
      if (!input.webhookUrl) throw new Error("Webhook URL is required");
      const url = await validateRemoteUrl(input.webhookUrl, {
        allowPrivateNetwork: input.allowPrivateNetwork,
      });
      this.redactor.register(input.webhookUrl);
      await this.secrets.set(secretKey(id, "webhook-url"), input.webhookUrl);
      Object.assign(settings, { endpointOrigin: url.origin, credentialsConfigured: true });
    } else if (input.type === "mcp") {
      if (!input.mcp) throw new Error("MCP settings are required");
      const url = await validateRemoteUrl(input.mcp.serverUrl, {
        allowPrivateNetwork: input.allowPrivateNetwork,
      });
      await this.secrets.set(secretKey(id, "mcp-server-url"), input.mcp.serverUrl);
      await this.secrets.set(secretKey(id, "mcp-tool-name"), input.mcp.toolName);
      if (input.mcp.bearerToken) {
        this.redactor.register(input.mcp.bearerToken);
        await this.secrets.set(secretKey(id, "mcp-bearer-token"), input.mcp.bearerToken);
      }
      Object.assign(settings, {
        endpointOrigin: url.origin,
        toolName: input.mcp.toolName,
        credentialsConfigured: true,
      });
    } else {
      Object.assign(settings, { localOnly: true });
    }
    const destination = NotificationDestinationSchema.parse({
      id,
      runId,
      type: input.type,
      name: input.name,
      destination: input.destination,
      targetIds: input.targetIds,
      enabled: input.enabled,
      allowPrivateNetwork: input.allowPrivateNetwork,
      includeSensitive: input.includeSensitive,
      simulationNotifications: input.simulationNotifications,
      settings,
      createdAt: now,
      updatedAt: now,
    });
    this.database.saveNotificationDestination(destination);
    return destination;
  }

  async deleteDestination(runId: string, destinationId: string): Promise<void> {
    const destination = this.database
      .listNotificationDestinations(runId, true)
      .find((entry) => entry.id === destinationId);
    if (!destination) throw new Error("Notification destination not found");
    this.database.deleteNotificationDestination(runId, destinationId);
    for (const field of [
      "smtp-host",
      "smtp-username",
      "smtp-password",
      "webhook-url",
      "mcp-server-url",
      "mcp-tool-name",
      "mcp-bearer-token",
    ]) {
      await this.secrets.delete(secretKey(destinationId, field)).catch(() => undefined);
    }
  }

  channelFor(destination: NotificationDestination): NotificationChannel {
    switch (destination.type) {
      case "smtp":
        return new SmtpNotificationChannel(destination, this.secrets);
      case "webhook":
        return new WebhookNotificationChannel(destination, this.secrets);
      case "mcp":
        return new McpNotificationChannel(destination, this.secrets);
      case "mock":
        return new MockNotificationChannel(destination, this.mockDeliveries);
    }
  }

  async testDestination(runId: string, destinationId: string): Promise<NotificationTestResult> {
    const destination = this.database
      .listNotificationDestinations(runId, true)
      .find((entry) => entry.id === destinationId);
    if (!destination) throw new Error("Notification destination not found");
    return this.channelFor(destination).test();
  }

  async evaluateMaterialChange(input: {
    runId: string;
    snapshot: WorldSnapshot;
    targetIds: string[];
    summary: string;
    evidenceIds: string[];
    simulated?: boolean;
  }): Promise<NotificationDelivery[]> {
    const isolated = isolateText(input.summary, { materialChange: true });
    if (isolated.securityState === "quarantined") return [];
    const destinations = this.database
      .listNotificationDestinations(input.runId)
      .filter(
        (destination) =>
          destination.targetIds.length === 0 ||
          input.targetIds.some((id) => destination.targetIds.includes(id)),
      )
      .filter((destination) => !input.simulated || destination.simulationNotifications);
    if (destinations.length === 0) return [];
    const agent = this.adapters.get(input.runId);
    if (!agent) return [];
    const world = this.database.worldView(input.runId);
    const relevantTargets = world.targets.filter((target) => input.targetIds.includes(target.id));
    const decisionResponse = await agent.run<unknown, NotificationDecision>({
      operation: "notify",
      instructions:
        "Decide whether this persisted material target change warrants a concise privacy-minimised alert. Do not select or modify destinations.",
      input: {
        material: true,
        targetNames: relevantTargets.map((target) => target.name),
        summary: isolated.text,
        evidenceCount: input.evidenceIds.length,
        duplicate: false,
      },
      schemaName: "NotificationDecision",
      onProgress: (progress) =>
        this.database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_notification_${nanoid(10)}`,
            runId: input.runId,
            lane: "LIVE WATCH",
            type: `notification.agent.${progress.stage}`,
            status:
              progress.stage === "completed"
                ? "completed"
                : progress.stage === "starting" || progress.stage === "thread-started"
                  ? "started"
                  : "progress",
            label: progress.message,
            createdAt: new Date().toISOString(),
            metadata: {
              operation: "notify",
              elapsedMs: progress.elapsedMs,
              ...(progress.threadId ? { threadId: progress.threadId } : {}),
              ...(progress.usage ? { usage: progress.usage } : {}),
            },
          }),
        ),
    });
    if (!decisionResponse.output.notify) {
      this.database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_notification_${nanoid(10)}`,
          runId: input.runId,
          lane: "LIVE WATCH",
          type: "notification.suppressed",
          status: "completed",
          label: "Configured agent assessed the material update; no alert was warranted",
          createdAt: new Date().toISOString(),
          metadata: { targetIds: input.targetIds, evidenceCount: input.evidenceIds.length },
        }),
      );
      return [];
    }
    validateAgentOutput(
      {
        text: JSON.stringify(decisionResponse.output),
        evidenceIds: input.evidenceIds,
        factual: true,
      },
      new Set(world.evidence.map((evidence) => evidence.id)),
    );

    const deliveries: NotificationDelivery[] = [];
    for (const destination of destinations) {
      const fingerprint = createHash("sha256")
        .update(
          `${input.snapshot.id}|${[...input.targetIds].sort().join(",")}|${isolated.contentHash}|${destination.id}`,
        )
        .digest("hex");
      if (this.database.hasNotificationFingerprint(input.runId, fingerprint)) continue;
      const targetLabel = privacyMinimisedTargetLabel(relevantTargets);
      const notification = AgentNotificationSchema.parse({
        id: `notification_${nanoid(10)}`,
        targetIds: input.targetIds,
        title: `${targetLabel} — new relevant change`,
        summary:
          decisionResponse.output.summary ??
          "A material evidence-backed change was added to the tracked world.",
        reason:
          decisionResponse.output.reason ??
          "The configured agent assessed this new target-linked change as useful to surface.",
        evidenceIds: input.evidenceIds,
        worldSnapshotId: input.snapshot.id,
        createdAt: new Date().toISOString(),
        destinationIds: [destination.id],
      });
      if (!this.database.saveNotification(input.runId, fingerprint, notification)) continue;
      const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
      if (this.database.recentDeliveryCount(destination.id, since) >= 6) {
        const skipped = NotificationDeliverySchema.parse({
          id: `delivery_${nanoid(10)}`,
          notificationId: notification.id,
          destinationId: destination.id,
          status: "skipped",
          attemptedAt: new Date().toISOString(),
          errorCode: "rate-limited",
          errorMessage: "Hourly notification limit reached",
        });
        this.database.saveNotificationDelivery(input.runId, skipped);
        this.database.saveEvent(
          ProcessingEventSchema.parse({
            id: `event_notification_${nanoid(10)}`,
            runId: input.runId,
            lane: "LIVE WATCH",
            type: "notification.rate-limited",
            status: "failed",
            label: `${destination.name} alert skipped by the hourly delivery limit`,
            createdAt: new Date().toISOString(),
            metadata: {
              notificationId: notification.id,
              destinationId: destination.id,
              destinationType: destination.type,
            },
          }),
        );
        deliveries.push(skipped);
        continue;
      }
      const channel = this.channelFor(destination);
      const result = await channel.send(notification);
      const delivery = NotificationDeliverySchema.parse({
        id: `delivery_${nanoid(10)}`,
        notificationId: notification.id,
        destinationId: destination.id,
        status: result.ok ? "sent" : "failed",
        attemptedAt: new Date().toISOString(),
        ...(!result.ok
          ? {
              errorCode: result.errorCode ?? "delivery-failed",
              errorMessage: this.redactor.redact(result.message),
            }
          : {}),
      });
      this.database.saveNotificationDelivery(input.runId, delivery);
      this.database.saveEvent(
        ProcessingEventSchema.parse({
          id: `event_notification_${nanoid(10)}`,
          runId: input.runId,
          lane: "LIVE WATCH",
          type: result.ok ? "notification.sent" : "notification.failed",
          status: result.ok ? "completed" : "failed",
          label: result.ok
            ? `${destination.name} material alert delivered`
            : `${destination.name} material alert delivery failed`,
          createdAt: new Date().toISOString(),
          metadata: {
            notificationId: notification.id,
            destinationId: destination.id,
            destinationType: destination.type,
            evidenceCount: notification.evidenceIds.length,
            ...(result.ok ? {} : { errorCode: delivery.errorCode }),
          },
        }),
      );
      deliveries.push(delivery);
    }
    return deliveries;
  }
}

function privacyMinimisedTargetLabel(targets: Target[]): string {
  if (targets.length === 0) return "Tracked target";
  if (targets.length > 1) return `${targets.length} tracked targets`;
  const target = targets[0]!;
  return target.name
    .replace(
      /\b\d{1,5}\s+[A-Za-z]+(?:\s+(?:Street|Road|Lane|Avenue|Drive))?\b/gi,
      "private location",
    )
    .slice(0, 80);
}
