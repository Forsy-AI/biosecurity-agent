import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Clock3, Database, Eye, FlaskConical, Radio, ShieldCheck, X } from "lucide-react";
import type { EvidenceRecord, ProcessingEvent, WorldView } from "@biosecurity/contracts";
import { api, subscribeToEvents } from "./api";
import { WorldVisual } from "./WorldVisual";

export function App() {
  const [world, setWorld] = useState<WorldView>();
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecord>();
  const [error, setError] = useState<string>();

  const refresh = useCallback(async () => {
    try {
      setWorld(await api.latest());
      setError(undefined);
    } catch (cause) {
      setError((cause as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const poll = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(poll);
  }, [refresh]);

  useEffect(() => {
    if (!world?.runId) return;
    let pending: number | undefined;
    const unsubscribe = subscribeToEvents(world.runId, () => {
      window.clearTimeout(pending);
      pending = window.setTimeout(() => void refresh(), 200);
    });
    return () => {
      window.clearTimeout(pending);
      unsubscribe();
    };
  }, [refresh, world?.runId]);

  if (!world) return <EmptyViewer error={error} />;
  return (
    <WorldViewer
      world={world}
      onEvidence={setSelectedEvidence}
      selectedEvidence={selectedEvidence}
    />
  );
}

function EmptyViewer({ error }: { error?: string }) {
  return (
    <main className="empty-viewer">
      <Brand />
      <div className="terminal-cue">
        <Radio size={20} />
        <div>
          <strong>No live world is available yet.</strong>
          <span>Start the terminal agent first:</span>
          <code>npx @forsy/biosecurity-agent</code>
        </div>
      </div>
      {error && <small>{error}</small>}
    </main>
  );
}

function Brand() {
  return (
    <div className="brand">
      <span className="brand-mark">
        <i />
        <i />
        <i />
      </span>
      <div>
        <strong>BIOSECURITY AGENT</strong>
        <small>VISUAL WORLD · CONTROLS LIVE IN THE CLI</small>
      </div>
    </div>
  );
}

function WorldViewer({
  world,
  selectedEvidence,
  onEvidence,
}: {
  world: WorldView;
  selectedEvidence?: EvidenceRecord;
  onEvidence: (evidence?: EvidenceRecord) => void;
}) {
  const events = useMemo(() => [...world.events].reverse().slice(0, 7), [world.events]);
  const snapshot = world.snapshots.at(-1);
  const simulationCount = world.snapshots.filter((item) => item.simulation).length;
  const simulation = snapshot?.simulation;
  const latestProtection = world.protections.at(-1);
  const status = simulation
    ? `SIMULATION · +${simulation.horizon.replace(/^(\d+)d$/i, "$1 DAYS").toUpperCase()}`
    : world.demo
      ? "FROZEN REPLAY"
      : "LIVE";
  const openEvidence = () => onEvidence(world.evidence[0]);
  return (
    <main className="viewer-shell">
      <header className="viewer-header">
        <Brand />
        <div className={`header-status ${simulation ? "simulation" : ""}`}>
          <span className="pulse" /> {status}{" "}
          <time>
            {new Date(snapshot?.asOf ?? Date.now()).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </time>
        </div>
      </header>
      <section className="world-stage">
        <div className="stage-meta">
          <div className="targets">
            {world.targets.map((target) => (
              <span key={target.id}>
                <i />
                {target.name}
              </span>
            ))}
          </div>
          <div className="world-counts">
            <span>
              <Database size={13} /> {world.artifacts.length} sources
            </span>
            <span>
              <Activity size={13} /> {world.entities.length} entities
            </span>
            <span>
              <Eye size={13} /> {world.claims.filter((claim) => claim.state === "observed").length}{" "}
              observed
            </span>
            {simulationCount > 0 && (
              <span>
                <FlaskConical size={13} /> {simulationCount} simulations
              </span>
            )}
          </div>
        </div>
        <WorldVisual world={world} onSelectEvidence={openEvidence} />
        <div className="event-overlay">
          <small>MEANINGFUL PIPELINE EVENTS</small>
          {events.map((event) => (
            <EventLine key={event.id} event={event} />
          ))}
        </div>
        {latestProtection && (
          <div className="protection-overlay">
            <small>
              <ShieldCheck size={12} /> PROTECTION
            </small>
            <strong>{latestProtection.title}</strong>
            <span>{latestProtection.summary}</span>
            <em>{latestProtection.evidenceIds.length} evidence links · approval-gated</em>
          </div>
        )}
      </section>
      <footer className="world-time">
        <span>NOW</span>
        <div className="time-track">
          {world.snapshots.map((item, index) => (
            <i
              key={item.id}
              className={item.simulation ? "simulated" : ""}
              style={{
                left: `${world.snapshots.length === 1 ? 2 : (index / (world.snapshots.length - 1)) * 98}%`,
              }}
            />
          ))}
        </div>
        <span>FUTURE</span>
        <small>
          <Clock3 size={12} /> World state is controlled by the terminal agent
        </small>
      </footer>
      {selectedEvidence && (
        <EvidencePanel evidence={selectedEvidence} onClose={() => onEvidence(undefined)} />
      )}
    </main>
  );
}

function EventLine({ event }: { event: ProcessingEvent }) {
  return (
    <div>
      <time>
        {new Date(event.createdAt).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        })}
      </time>
      <b>{event.lane.split(" ")[0]}</b>
      <span>{event.label}</span>
    </div>
  );
}

function EvidencePanel({ evidence, onClose }: { evidence: EvidenceRecord; onClose: () => void }) {
  return (
    <aside className="evidence-panel">
      <button aria-label="Close evidence" onClick={onClose}>
        <X size={18} />
      </button>
      <small>
        {evidence.status.toUpperCase()} · {evidence.sourceClass.toUpperCase()}
      </small>
      <h2>{evidence.sourceTitle}</h2>
      <p>{evidence.claim}</p>
      <blockquote>{evidence.excerpt}</blockquote>
      <dl>
        <dt>Target relevance</dt>
        <dd>{evidence.targetRelevance}</dd>
        <dt>Confidence</dt>
        <dd>{Math.round(evidence.confidence * 100)}%</dd>
        <dt>Retrieved</dt>
        <dd>{new Date(evidence.retrievedAt).toLocaleString()}</dd>
        <dt>Licence</dt>
        <dd>{evidence.licenceNotes}</dd>
      </dl>
      {evidence.sourceUrl && (
        <a href={evidence.sourceUrl} target="_blank" rel="noreferrer">
          Open original source
        </a>
      )}
    </aside>
  );
}
