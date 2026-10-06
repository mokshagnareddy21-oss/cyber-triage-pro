import { buildDecision, buildTimeline, routeConfidence } from "./decision";
import { deriveJev, geminiFixture, geminiUnavailable } from "./fixtures";
import { simulateLatency } from "./telemetry";
import { DEFAULT_PREFERENCES, routeForProbability, type Preferences } from "./thresholds";
import type {
  AuditEntry,
  GeminiInvestigation,
  JevDecision,
  QueueMetrics,
  ReviewStatus,
  SecurityEvent,
  TriageResult,
} from "./types";

export interface AnalyzeOptions {
  /** Analyst posture; defaults to the shared DEFAULT_PREFERENCES. */
  preferences?: Partial<Preferences>;
  /** Supply a live Jev result instead of the deterministic fixture. */
  jev?: JevDecision;
  /** Supply a live Gemini result instead of the deterministic fixture. */
  gemini?: GeminiInvestigation | null;
  /** True when the deep model was requested but failed. */
  escalationFailed?: boolean;
  reviewStatus?: ReviewStatus;
  /** Override measured latency (the backend passes real timings). */
  latency?: { jevMs: number; geminiMs: number; totalMs: number };
}

/**
 * The single routing pipeline (spec §34):
 *
 *   validate → fast triage → route → contain / dismiss / escalate
 *   → score alternatives → build the decision → emit the timeline → audit
 *
 * The browser runs it with deterministic fixtures when no backend is
 * reachable; the Express service runs the same function with live model
 * output. Both produce byte-identical structure, so the UI never branches on
 * where the numbers came from — only on the `source` label it displays.
 */
export function analyzeSecurityEvent(
  event: SecurityEvent,
  options: AnalyzeOptions = {},
): TriageResult {
  const preferences: Preferences = { ...DEFAULT_PREFERENCES, ...options.preferences };
  const jev = options.jev ?? deriveJev(event);
  const route = routeForProbability(jev.maliciousProbability);

  const latency =
    options.latency ??
    (options.jev
      ? {
          jevMs: options.jev.latencyMs,
          geminiMs: 0,
          totalMs: options.jev.latencyMs + 12,
        }
      : simulateLatency(event.id, route));

  let gemini: GeminiInvestigation | null = null;
  let escalationFailed = false;

  if (route === "GRAY") {
    if (options.gemini === null) {
      escalationFailed = true;
      gemini = geminiUnavailable("The deep reasoning model did not return a result.");
    } else if (options.gemini) {
      gemini = options.gemini;
      latency.geminiMs = gemini.latencyMs;
    } else {
      gemini = geminiFixture({ event, jev });
      latency.geminiMs = gemini.latencyMs;
    }
    latency.totalMs = latency.jevMs + latency.geminiMs + 12;
    escalationFailed = escalationFailed || gemini.source === "UNAVAILABLE";
  }

  const scoreInput = { event, jev, route, preferences };

  // Gray-zone events that failed escalation must never auto-resolve.
  const override =
    route === "GRAY" && gemini?.source === "UNAVAILABLE" ? ("HUMAN REVIEW" as const) : undefined;
  const decision = buildDecision(scoreInput, override);

  // For a healthy gray-zone escalation, the deep model's recommendation wins —
  // that is the entire point of spending the call.
  if (route === "GRAY" && gemini && gemini.source !== "UNAVAILABLE") {
    const deepPick = decision.ranked.find((entry) => entry.action === gemini.recommendedAction);
    if (deepPick) {
      decision.action = gemini.recommendedAction;
      decision.why = `${gemini.recommendedAction} is carried forward from deep forensics. ${decision.why}`;
    }
  }

  const containment =
    route === "CONTAIN"
      ? { action: decision.action, serverId: event.serverId, simulated: true as const }
      : null;

  const timeline = buildTimeline({
    event,
    jev,
    route,
    containment,
    gemini,
    decision,
    latency,
    escalationFailed,
    reviewStatus: options.reviewStatus,
  });

  return {
    event,
    jev,
    route,
    containment,
    gemini: route === "GRAY" ? gemini : null,
    decision,
    timeline,
    latency,
    reviewStatus: options.reviewStatus ?? "PENDING",
    aiMode: jev.source,
    escalationFailed,
  };
}

/** Append-only audit line for one triaged event. */
export function auditFor(result: TriageResult, actor = "system"): AuditEntry[] {
  const entries: AuditEntry[] = [
    {
      id: `AUD-${result.event.id}-01`,
      timestamp: result.event.timestamp,
      actor,
      eventId: result.event.id,
      action: "EVENT_INGESTED",
      detail: `${result.event.source} → ${result.event.serverId}`,
    },
    {
      id: `AUD-${result.event.id}-02`,
      timestamp: result.event.timestamp + 1,
      actor: "jev",
      eventId: result.event.id,
      action: "JEV_TRIAGE",
      detail: `p=${result.jev.maliciousProbability.toFixed(2)} · ${result.jev.classification} · severity ${result.jev.severityScore}/10 · ${result.jev.source}`,
    },
    {
      id: `AUD-${result.event.id}-03`,
      timestamp: result.event.timestamp + 2,
      actor: "routing-engine",
      eventId: result.event.id,
      action: `ROUTE_${result.route}`,
      detail: `threshold routing · confidence ${routeConfidence(result.jev.maliciousProbability, result.route).toFixed(2)} · ${result.latency.totalMs} ms`,
    },
    {
      id: `AUD-${result.event.id}-04`,
      timestamp: result.event.timestamp + 3,
      actor: "decision-engine",
      eventId: result.event.id,
      action: "RECOMMENDATION",
      detail: `${result.decision.action} · confidence ${(result.decision.confidence * 100).toFixed(0)}% · ${result.gemini ? `gemini ${result.gemini.source}` : "gemini not called"}`,
    },
  ];

  if (result.containment) {
    entries.push({
      id: `AUD-${result.event.id}-05`,
      timestamp: result.event.timestamp + 4,
      actor: "containment-service",
      eventId: result.event.id,
      action: "ISOLATE_HOST",
      detail: `${result.containment.serverId} → ISOLATED (simulated state change, demo environment)`,
    });
  }

  if (result.reviewStatus !== "PENDING" && result.reviewedBy) {
    entries.push({
      id: `AUD-${result.event.id}-06`,
      timestamp: result.reviewedAt ?? result.event.timestamp + 5,
      actor: result.reviewedBy,
      eventId: result.event.id,
      action: `REVIEW_${result.reviewStatus}`,
      detail: result.reviewNote ?? "Analyst decision recorded.",
    });
  }

  return entries;
}

/** Aggregate the queue into the header metrics (spec §16, §39). */
export function computeMetrics(results: TriageResult[]): QueueMetrics {
  if (results.length === 0) {
    return {
      ingested: 0,
      contained: 0,
      dismissed: 0,
      grayZone: 0,
      geminiCalls: 0,
      geminiCallsAvoided: 0,
      pendingReview: 0,
      reviewed: 0,
      avgTotalLatencyMs: 0,
      avgJevLatencyMs: 0,
    };
  }

  let contained = 0;
  let dismissed = 0;
  let gray = 0;
  let geminiCalls = 0;
  let pending = 0;
  let reviewed = 0;
  let totalLatency = 0;
  let jevLatency = 0;

  for (const result of results) {
    if (result.route === "CONTAIN") contained += 1;
    else if (result.route === "DISMISS") dismissed += 1;
    else gray += 1;
    if (result.gemini && result.gemini.source !== "UNAVAILABLE") geminiCalls += 1;
    if (result.reviewStatus === "PENDING") pending += 1;
    else reviewed += 1;
    totalLatency += result.latency.totalMs;
    jevLatency += result.latency.jevMs;
  }

  return {
    ingested: results.length,
    contained,
    dismissed,
    grayZone: gray,
    geminiCalls,
    geminiCallsAvoided: results.length - geminiCalls,
    pendingReview: pending,
    reviewed,
    avgTotalLatencyMs: Math.round(totalLatency / results.length),
    avgJevLatencyMs: Math.round(jevLatency / results.length),
  };
}

/** Percent of deep-model calls the router prevented. */
export function routingEfficiency(metrics: QueueMetrics): number {
  if (metrics.ingested === 0) return 0;
  return Math.round((metrics.geminiCallsAvoided / metrics.ingested) * 100);
}
