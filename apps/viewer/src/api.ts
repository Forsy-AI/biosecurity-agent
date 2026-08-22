import type { ProcessingEvent, WorldView } from "@biosecurity/contracts";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options?.body instanceof FormData ? {} : { "content-type": "application/json" }),
      ...options?.headers,
    },
  });
  const body = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? `Request failed with HTTP ${response.status}`);
  return body;
}

export const api = {
  latest: () => request<WorldView>("/api/runs/latest"),
};

export function subscribeToEvents(
  runId: string,
  onEvent: (event: ProcessingEvent) => void,
): () => void {
  const source = new EventSource(`/api/events/${runId}`);
  source.addEventListener("processing", (message) =>
    onEvent(JSON.parse((message as MessageEvent).data) as ProcessingEvent),
  );
  return () => source.close();
}
