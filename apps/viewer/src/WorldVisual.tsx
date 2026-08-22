import { useEffect, useMemo, useRef } from "react";
import maplibregl from "maplibre-gl";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { Globe2, MapPin } from "lucide-react";
import type { WorldView } from "@biosecurity/contracts";

type IntelNodeData = {
  label: string;
  kind: string;
  state: "observed" | "inferred" | "simulated";
  detail?: string;
};

function IntelNode({ data }: NodeProps<Node<IntelNodeData>>) {
  return (
    <div className={`intel-node ${data.state}`}>
      <Handle type="target" position={Position.Left} />
      <span>
        {data.kind === "target"
          ? "◎"
          : data.kind === "plant"
            ? "⌁"
            : data.kind === "animal"
              ? "◇"
              : "•"}
      </span>
      <div>
        <small>{data.kind}</small>
        <strong>{data.label}</strong>
        {data.detail && <em>{data.detail}</em>}
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { intel: IntelNode };

export function WorldVisual({
  world,
  onSelectEvidence,
}: {
  world: WorldView;
  onSelectEvidence: () => void;
}) {
  const mapRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!mapRef.current) return;
    const locations = [
      ...world.targets.flatMap((target) =>
        target.locations.map((location) => ({ ...location, target: true })),
      ),
      ...world.entities.flatMap((entity) =>
        entity.locations.map((location) => ({ ...location, target: false })),
      ),
    ]
      .filter((location) => location.longitude !== undefined && location.latitude !== undefined)
      .reduce<
        Array<{
          label: string;
          latitude?: number;
          longitude?: number;
          target: boolean;
        }>
      >((unique, location) => {
        const existing = unique.find(
          (candidate) =>
            Math.abs((candidate.latitude ?? 0) - (location.latitude ?? 0)) < 0.002 &&
            Math.abs((candidate.longitude ?? 0) - (location.longitude ?? 0)) < 0.002,
        );
        if (!existing) unique.push(location);
        else if (location.target) existing.target = true;
        return unique;
      }, []);
    const first = locations[0];
    const map = new maplibregl.Map({
      container: mapRef.current,
      style: {
        version: 8,
        sources: {},
        layers: [
          { id: "background", type: "background", paint: { "background-color": "#101619" } },
        ],
      },
      center: first ? [first.longitude!, first.latitude!] : [20, 18],
      zoom: first ? 1.15 : 1.2,
      attributionControl: false,
      interactive: true,
    });
    const bounds = new maplibregl.LngLatBounds();
    for (const location of locations) {
      const element = document.createElement("button");
      element.className = `map-marker ${location.target ? "target" : "evidence"}`;
      element.setAttribute("aria-label", location.label);
      const dot = document.createElement("span");
      const label = document.createElement("em");
      label.textContent = location.label;
      element.append(dot, label);
      element.onclick = onSelectEvidence;
      new maplibregl.Marker({ element })
        .setLngLat([location.longitude!, location.latitude!])
        .addTo(map);
      bounds.extend([location.longitude!, location.latitude!]);
    }
    if (locations.length > 1) map.fitBounds(bounds, { padding: 62, maxZoom: 2.7, duration: 0 });
    return () => map.remove();
  }, [onSelectEvidence, world.entities, world.targets]);

  const graph = useMemo(() => {
    const nodes: Node<IntelNodeData>[] = [];
    const edges: Edge[] = [];
    world.targets.forEach((target, index) =>
      nodes.push({
        id: target.id,
        type: "intel",
        position: { x: 35, y: 35 + index * 115 },
        data: {
          label: target.name,
          kind: "target",
          state: "observed",
          detail: target.inferredKind,
        },
      }),
    );
    world.entities.slice(0, 11).forEach((entity, index) => {
      const claim = world.claims.find((item) => item.subject.id === entity.id);
      const evidence = world.evidence.find((item) => item.claim.startsWith(entity.label));
      nodes.push({
        id: entity.id,
        type: "intel",
        position: { x: 235 + (index % 2) * 205, y: 12 + Math.floor(index / 2) * 92 },
        data: {
          label: entity.label,
          kind: entity.kind,
          state: claim?.state ?? "inferred",
          detail: claim?.predicate,
        },
      });
      const target =
        world.targets.find((item) => evidence?.targetIds.includes(item.id)) ??
        world.targets[index % world.targets.length];
      if (target)
        edges.push({
          id: `edge-${target.id}-${entity.id}`,
          source: target.id,
          target: entity.id,
          animated: claim?.state !== "simulated",
          className: claim?.state ?? "inferred",
        });
    });
    world.claims
      .filter((claim) => claim.state === "simulated")
      .slice(0, 3)
      .forEach((claim, index) => {
        const target = world.targets.find((item) => item.id === claim.subject.id);
        nodes.push({
          id: claim.id,
          type: "intel",
          position: { x: 670, y: 60 + index * 145 },
          data: {
            label: target ? `${target.name} · +14 days` : `Future impact ${index + 1}`,
            kind: "future",
            state: "simulated",
            detail: String(claim.object),
          },
        });
        if (target)
          edges.push({
            id: `edge-${target.id}-${claim.id}`,
            source: target.id,
            target: claim.id,
            animated: true,
            className: "simulated",
          });
      });
    return { nodes, edges };
  }, [world]);

  return (
    <div className="adaptive-visual">
      <div className="visual-map">
        <div className="visual-label">
          <MapPin size={13} /> GEOGRAPHIC CONTEXT
        </div>
        <div className="map-grid" />
        <div ref={mapRef} className="maplibre-container" />
        <div className="map-caption">
          <Globe2 size={13} />
          <span>Offline coordinate view</span>
          <small>No third-party map tiles requested</small>
        </div>
      </div>
      <div className="visual-graph">
        <div className="visual-label">RELATIONSHIP GRAPH</div>
        <ReactFlow
          nodes={graph.nodes}
          edges={graph.edges}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.5}
          maxZoom={1.4}
          nodesDraggable={false}
          proOptions={{ hideAttribution: true }}
          onNodeClick={onSelectEvidence}
        >
          <Background color="#283235" gap={22} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
    </div>
  );
}
