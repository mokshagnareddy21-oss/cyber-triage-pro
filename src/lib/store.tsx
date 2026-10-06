import { useAuth } from "@/hooks/use-auth";
import { ApiError, API_BASE, apiFetch } from "@/lib/api";
import {
  DEFAULT_PREFERENCES,
  analyzeSecurityEvent,
  auditFor,
  buildFleet,
  computeMetrics,
  generateEvent,
  nextEventId,
  resetEventCounter,
  routingEfficiency,
  SCENARIOS,
  scenarioToEvent,
  type AuditEntry,
  type QueueMetrics,
  type ReviewStatus,
  type SecurityEvent,
  type SimServer,
  type TriageResult,
} from "@/core";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";

const SEED_COUNT = 26;
const MAX_QUEUE = 140;
const DEFAULT_SPEED_MS = 2600;

export type Transport = "backend" | "local";

export interface ReviewDraft {
  status: Extract<ReviewStatus, "APPROVED" | "OVERRIDDEN" | "DISMISSED">;
  note: string;
  action?: string;
}

interface TriageContextValue {
  fleet: SimServer[];
  results: TriageResult[];
  metrics: QueueMetrics;
  efficiency: number;
  audit: AuditEntry[];
  streaming: boolean;
  speedMs: number;
  transport: Transport;
  degraded: boolean;
  /** Which engine the backend reports it is running — never inferred from UI. */
  aiMode: "LIVE" | "DEMO_FIXTURE";
  selectedId: string | null;
  transient: Record<string, string>;
  startStream: () => void;
  stopStream: () => void;
  setSpeed: (ms: number) => void;
  step: (scenarioKey?: string) => Promise<void>;
  reset: () => void;
  select: (id: string | null) => void;
  review: (eventId: string, draft: ReviewDraft) => Promise<void>;
}

const TriageContext = createContext<TriageContextValue | null>(null);

function seedHistory(fleet: SimServer[]): { results: TriageResult[]; audit: AuditEntry[] } {
  resetEventCounter(0);
  const now = Date.now();
  const results: TriageResult[] = [];
  const audit: AuditEntry[] = [];
  for (let index = SEED_COUNT; index >= 1; index--) {
    const timestamp = now - index * 95_000 - Math.round(Math.random() * 20_000);
    const event = generateEvent({ fleet, timestamp, seed: timestamp + index });
    const result = analyzeSecurityEvent(event, { preferences: DEFAULT_PREFERENCES });
    results.push(result);
    audit.push(...auditFor(result, "system"));
  }
  results.sort((a, b) => b.event.timestamp - a.event.timestamp);
  return { results, audit };
}

export function TriageProvider({ children }: { children: ReactNode }) {
  const { mode, user } = useAuth();
  const initialFleet = useMemo(() => buildFleet(50), []);
  const initial = useMemo(() => seedHistory(initialFleet), [initialFleet]);

  const [fleet, setFleet] = useState<SimServer[]>(initialFleet);
  const [results, setResults] = useState<TriageResult[]>(initial.results);
  const [audit, setAudit] = useState<AuditEntry[]>(initial.audit);
  const [streaming, setStreaming] = useState(true);
  const [speedMs, setSpeedMs] = useState(DEFAULT_SPEED_MS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [transient, setTransient] = useState<Record<string, string>>({});
  const [transportOverride, setTransportOverride] = useState<Transport | null>(null);
  const transport: Transport = transportOverride ?? (mode === "backend" ? "backend" : "local");
  const [degraded, setDegraded] = useState(false);
  const [aiMode, setAiMode] = useState<"LIVE" | "DEMO_FIXTURE">("DEMO_FIXTURE");

  const timerRef = useRef<number | null>(null);
  const resultsRef = useRef(results);
  const fleetRef = useRef(fleet);
  const transportRef = useRef<Transport>(transport);

  // Refs are mirrored from state in effects — never during render.
  useEffect(() => {
    resultsRef.current = results;
  }, [results]);
  useEffect(() => {
    fleetRef.current = fleet;
  }, [fleet]);
  useEffect(() => {
    transportRef.current = transport;
  }, [transport]);

  useEffect(() => {
    if (mode !== "backend") return;
    let cancelled = false;
    void (async () => {
      try {
        const [servers, health] = await Promise.all([
          apiFetch<SimServer[]>("/api/servers"),
          apiFetch<{ ai?: { jev?: string } }>("/api/health"),
        ]);
        if (cancelled) return;
        if (Array.isArray(servers) && servers.length > 0) setFleet(servers);
        if (health?.ai?.jev) {
          setAiMode(health.ai.jev === "LIVE" ? "LIVE" : "DEMO_FIXTURE");
        }
      } catch {
        if (!cancelled) {
          setTransportOverride("local");
          setDegraded(true);
          setAiMode("DEMO_FIXTURE");
          toast.warning("Backend unreachable", {
            description: "Running the local deterministic engine so the console keeps working.",
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mode]);

  const applyToServer = useCallback((result: TriageResult) => {
    const serverId = result.event.serverId;
    const nextStatus =
      result.route === "CONTAIN" ? "ISOLATED" : result.route === "GRAY" ? "INVESTIGATING" : "MONITORING";
    const label =
      result.route === "CONTAIN"
        ? "ISOLATING…"
        : result.route === "GRAY"
          ? "ESCALATING…"
          : "RESUMED";

    setTransient((previous) => ({ ...previous, [serverId]: label }));
    setFleet((previous) =>
      previous.map((server) =>
        server.serverId === serverId
          ? {
              ...server,
              status: nextStatus,
              threatScore: Math.max(
                server.threatScore,
                Math.round(result.jev.maliciousProbability * 100),
              ),
              cpu: Math.min(99, server.cpu + Math.round(result.jev.severityScore * 3)),
              lastEventAt: result.event.timestamp,
            }
          : server,
      ),
    );

    const handle = window.setTimeout(() => {
      setTransient((previous) => {
        if (previous[serverId] !== label) return previous;
        const next = { ...previous };
        delete next[serverId];
        return next;
      });
    }, 1400);
    return () => window.clearTimeout(handle);
  }, []);

  const ingest = useCallback(
    async (scenarioKey?: string) => {
      const scenario = scenarioKey ? SCENARIOS.find((entry) => entry.key === scenarioKey) : undefined;
      let result: TriageResult;

      if (transportRef.current === "backend" && API_BASE) {
        try {
          result = await apiFetch<TriageResult>("/api/events/analyze", {
            method: "POST",
            body: JSON.stringify(scenario ? { scenarioKey: scenario.key } : {}),
            timeoutMs: 12000,
          });
        } catch (error) {
          transportRef.current = "local";
          setTransportOverride("local");
          setDegraded(true);
          toast.error("Falling back to the local engine", {
            description:
              error instanceof ApiError
                ? error.message
                : "The decision API did not respond in time.",
          });
          result = analyseLocally(fleetRef.current, scenarioKey);
        }
      } else {
        result = analyseLocally(fleetRef.current, scenarioKey);
      }

      applyToServer(result);
      const entries = auditFor(result, user?.email ?? "analyst");
      setResults((previous) => [result, ...previous].slice(0, MAX_QUEUE));
      setAudit((previous) => [...entries, ...previous].slice(0, MAX_QUEUE * 4));

      // Containment is already visible as a red row and an ISOLATED chip; only
      // genuinely actionable surprises interrupt the analyst.
      if (result.escalationFailed) {
        toast.warning("Deep analysis unavailable", {
          description: `${result.event.id} · HUMAN REVIEW REQUIRED — the event stays on the queue.`,
        });
      }
      if (scenarioKey) {
        toast.info(`Scenario · ${scenario?.name ?? scenarioKey}`, {
          description: `${routeName(result.route)} → ${result.decision.action} · p=${result.jev.maliciousProbability.toFixed(2)}`,
        });
      }
      return result;
    },
    [applyToServer, user?.email],
  );

  const ingestRef = useRef(ingest);
  useEffect(() => {
    ingestRef.current = ingest;
  }, [ingest]);

  useEffect(() => {
    if (!streaming) {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      return;
    }
    timerRef.current = window.setInterval(() => {
      void ingestRef.current();
    }, speedMs);
    return () => {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [streaming, speedMs]);

  const review = useCallback(
    async (eventId: string, draft: ReviewDraft) => {
      const target = resultsRef.current.find((entry) => entry.event.id === eventId);
      if (!target) return;

      if (transportRef.current === "backend" && API_BASE) {
        try {
          await apiFetch(`/api/events/${eventId}/review`, {
            method: "POST",
            body: JSON.stringify(draft),
          });
        } catch (error) {
          toast.error("Review not persisted on the server", {
            description: error instanceof ApiError ? error.message : "Request failed.",
          });
          return;
        }
      }

      const actor = user?.email ?? "analyst";
      setResults((previous) =>
        previous.map((entry) =>
          entry.event.id === eventId
            ? {
                ...entry,
                reviewStatus: draft.status,
                reviewedBy: actor,
                reviewNote: draft.note,
                reviewedAt: Date.now(),
                decision:
                  draft.status === "OVERRIDDEN" && draft.action
                    ? { ...entry.decision, action: draft.action as TriageResult["decision"]["action"] }
                    : entry.decision,
              }
            : entry,
        ),
      );
      setAudit((previous) => [
        {
          id: `AUD-${eventId}-R${previous.length}`,
          timestamp: Date.now(),
          actor,
          eventId,
          action: `REVIEW_${draft.status}`,
          detail: draft.action
            ? `${draft.action}${draft.note ? ` · ${draft.note}` : ""}`
            : draft.note || "Decision recorded.",
        },
        ...previous,
      ]);
      toast.success(`Marked ${draft.status.toLowerCase()}`, {
        description: `${eventId} · recorded on the immutable audit trail.`,
      });
    },
    [user?.email],
  );

  const reset = useCallback(() => {
    setStreaming(false);
    const nextFleet = buildFleet(50);
    const seeded = seedHistory(nextFleet);
    setFleet(nextFleet);
    setResults(seeded.results);
    setAudit(seeded.audit);
    setSelectedId(null);
    setTransient({});
    setDegraded(false);
    setTransportOverride(null);
    toast.success("Simulation reset", { description: "Fleet restored, queue re-seeded." });
  }, [mode]);

  const metrics = useMemo(() => computeMetrics(results), [results]);
  const efficiency = useMemo(() => routingEfficiency(metrics), [metrics]);

  const value = useMemo<TriageContextValue>(
    () => ({
      fleet,
      results,
      metrics,
      efficiency,
      audit,
      streaming,
      speedMs,
      transport,
      degraded,
      aiMode,
      selectedId,
      transient,
      startStream: () => setStreaming(true),
      stopStream: () => setStreaming(false),
      setSpeed: setSpeedMs,
      step: (scenarioKey?: string) => ingest(scenarioKey).then(() => undefined),
      reset,
      select: setSelectedId,
      review,
    }),
    [fleet, results, metrics, efficiency, audit, streaming, speedMs, transport, degraded, aiMode, selectedId, transient, ingest, reset, review],
  );

  return <TriageContext.Provider value={value}>{children}</TriageContext.Provider>;
}

function routeName(route: TriageResult["route"]): string {
  if (route === "CONTAIN") return "CONTAIN";
  if (route === "DISMISS") return "DISMISS";
  return "ESCALATE";
}

function analyseLocally(fleet: SimServer[], scenarioKey?: string): TriageResult {
  if (scenarioKey) {
    const scenario = SCENARIOS.find((entry) => entry.key === scenarioKey);
    if (scenario) {
      const event = scenarioToEvent(scenario, Date.now(), nextEventId());
      return analyzeSecurityEvent(event, { preferences: DEFAULT_PREFERENCES });
    }
  }
  const event: SecurityEvent = generateEvent({ fleet });
  return analyzeSecurityEvent(event, { preferences: DEFAULT_PREFERENCES });
}

export function useTriage(): TriageContextValue {
  const context = useContext(TriageContext);
  if (!context) throw new Error("useTriage must be used inside <TriageProvider>");
  return context;
}
