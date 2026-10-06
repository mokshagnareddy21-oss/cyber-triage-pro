import { applySimulatedAction } from "./containmentService";
import { runGemini } from "./geminiService";
import { runJev } from "./jevService";
import {
  AuditLog,
  DecisionRecord as DecisionRecordModel,
  GeminiInvestigation as GeminiModel,
  JevDecision as JevDecisionModel,
  SecurityEvent,
  Server,
  type SecurityEventDoc,
} from "../models";
import {
  DEFAULT_PREFERENCES,
  analyzeSecurityEvent as runCore,
  auditFor,
  routeForProbability,
  type GeminiInvestigation,
  type JevDecision,
  type Preferences,
  type SecurityEvent as TriageEvent,
  type TriageResult,
} from "../../../shared";

/**
 * AI routing engine (spec §34). One function, eleven steps:
 *
 *   validate → call Jev → calculate route → save Jev result →
 *   execute simulated containment / dismiss / escalate to Gemini →
 *   calculate final recommendation → save decision → create audit log →
 *   return the complete structured result.
 *
 * The scoring, timeline and explanations come from the shared core, so the API
 * and the browser console can never disagree about a decision.
 */

export interface AnalyzeRequest {
  scenarioEvent?: TriageEvent;
  generatedEvent?: TriageEvent;
  preferences?: Partial<Preferences>;
  actor?: string;
}

function toTriageEvent(doc: SecurityEventDoc): TriageEvent {
  return {
    id: doc.eventId,
    timestamp: new Date(doc.timestamp).getTime(),
    serverId: doc.serverId,
    eventType: doc.eventType,
    payload: doc.payload,
    source: doc.source,
    user: doc.user ?? undefined,
    networkContext: doc.networkContext ?? undefined,
    scope: doc.scope as TriageEvent["scope"],
    assetCriticality: doc.assetCriticality,
    dataSensitivity: doc.dataSensitivity,
  };
}

async function persistEvent(event: TriageEvent): Promise<void> {
  await SecurityEvent.updateOne(
    { eventId: event.id },
    {
      $setOnInsert: {
        eventId: event.id,
        timestamp: new Date(event.timestamp),
        serverId: event.serverId,
        eventType: event.eventType,
        payload: event.payload,
        source: event.source,
        user: event.user ?? null,
        networkContext: event.networkContext ?? null,
        scope: event.scope,
        assetCriticality: event.assetCriticality,
        dataSensitivity: event.dataSensitivity,
        simulated: true,
      },
    },
    { upsert: true },
  );
}

export async function analyzeSecurityEvent(
  request: AnalyzeRequest,
): Promise<TriageResult> {
  const event = request.scenarioEvent ?? request.generatedEvent;
  if (!event) throw new Error("No event supplied to the routing engine.");

  const preferences: Preferences = { ...DEFAULT_PREFERENCES, ...request.preferences };
  const actor = request.actor ?? "system";

  // 1–2. validate (already typed) and call the fast model
  const jevResult = await runJev(event);

  // 3. route
  const route = routeForProbability(jevResult.decision.maliciousProbability);

  // 4. save the Jev result
  await JevDecisionModel.updateOne(
    { eventId: event.id },
    {
      $set: {
        eventId: event.id,
        maliciousProbability: jevResult.decision.maliciousProbability,
        classification: jevResult.decision.classification,
        severityScore: jevResult.decision.severityScore,
        confidence: jevResult.decision.confidence,
        noul: jevResult.decision.noul,
        choice: jevResult.decision.choice,
        score: jevResult.decision.score,
        evidence: jevResult.decision.evidence,
        source: jevResult.decision.source,
        rawResponse: jevResult.raw,
        latencyMs: jevResult.decision.latencyMs,
      },
    },
    { upsert: true },
  );

  await persistEvent(event);

  // 5. execute simulated containment when confidence is high
  if (route === "CONTAIN") {
    const decided = runCore(event, {
      preferences,
      jev: jevResult.decision,
      gemini: null,
      escalationFailed: false,
    });
    await applySimulatedAction(decided.decision.action, event.serverId);
    return finalise(decided, event, jevResult.decision, actor, preferences, route);
  }

  // 6. dismiss below threshold — no deep-model call is spent
  if (route === "DISMISS") {
    await applySimulatedAction("ALLOW", event.serverId);
    const decided = runCore(event, { preferences, jev: jevResult.decision });
    return finalise(decided, event, jevResult.decision, actor, preferences, route);
  }

  // 7. gray zone — throttle, then escalate to Gemini
  await applySimulatedAction("THROTTLE", event.serverId);
  const geminiResult = await runGemini(event, jevResult.decision);
  const decided = runCore(event, {
    preferences,
    jev: jevResult.decision,
    gemini: geminiResult.investigation,
    escalationFailed: geminiResult.investigation.source === "UNAVAILABLE",
  });

  await GeminiModel.updateOne(
    { eventId: event.id },
    {
      $set: {
        eventId: event.id,
        summary: geminiResult.investigation.summary,
        classification: geminiResult.investigation.classification,
        rootCause: geminiResult.investigation.rootCause,
        evidence: geminiResult.investigation.evidence,
        mitre: geminiResult.investigation.mitre,
        impact: geminiResult.investigation.impact,
        risks: geminiResult.investigation.risks,
        recommendedAction: geminiResult.investigation.recommendedAction,
        containment: geminiResult.investigation.containment,
        remediation: geminiResult.investigation.remediation,
        confidenceExplanation: geminiResult.investigation.confidenceExplanation,
        alternatives: geminiResult.investigation.alternatives,
        remediationCode: geminiResult.investigation.remediationCode,
        remediationLanguage: geminiResult.investigation.remediationLanguage,
        source: geminiResult.investigation.source,
        rawResponse: geminiResult.raw,
        latencyMs: geminiResult.investigation.latencyMs,
      },
    },
    { upsert: true },
  );

  return finalise(decided, event, jevResult.decision, actor, preferences, route);
}

async function finalise(
  decided: TriageResult,
  event: TriageEvent,
  jev: TriageResult["jev"],
  actor: string,
  preferences: Preferences,
  route: TriageResult["route"],
): Promise<TriageResult> {
  // 8. save the decision record
  await DecisionRecordModel.updateOne(
    { eventId: event.id },
    {
      $set: {
        eventId: event.id,
        route,
        recommendedAction: decided.decision.action,
        alternativeActions: decided.decision.alternatives.map((entry) => ({
          action: entry.action,
          score: entry.score,
        })),
        decisionFactors: decided.decision.factors,
        riskTolerance: preferences.riskTolerance,
        securitySensitivity: preferences.securitySensitivity,
        availabilityPriority: preferences.availabilityPriority,
        confidence: decided.decision.confidence,
        explanation: decided.decision.why,
      },
    },
    { upsert: true },
  );

  // 9. create the audit log
  const entries = auditFor(decided, actor);
  await AuditLog.insertMany(
    entries.map((entry) => ({
      timestamp: new Date(entry.timestamp),
      actor: entry.actor,
      eventId: entry.eventId,
      action: entry.action,
      metadata: { detail: entry.detail, source: decided.jev.source },
      simulation: true,
    })),
    { ordered: false },
  ).catch(() => undefined);

  // 10. mirror the event's derived fields
  await SecurityEvent.updateOne(
    { eventId: event.id },
    {
      $set: {
        probability: jev.maliciousProbability,
        classification: jev.classification,
        severity: jev.severityScore,
        routing: route,
        jevLatencyMs: decided.latency.jevMs,
        geminiLatencyMs: decided.latency.geminiMs,
        totalDecisionLatencyMs: decided.latency.totalMs,
      },
    },
  );

  await Server.updateOne(
    { serverId: event.serverId },
    { $set: { lastEventAt: new Date(event.timestamp) } },
  );

  return decided;
}

/** Re-run analysis for an already-stored event (used by GET /api/events/:id). */
export async function reanalyse(doc: SecurityEventDoc): Promise<TriageResult> {
  const event = toTriageEvent(doc);
  const stored = await JevDecisionModel.findOne({ eventId: doc.eventId });
  const investigation = await GeminiModel.findOne({ eventId: doc.eventId });

  const jev: JevDecision | undefined = stored
    ? {
        maliciousProbability: stored.maliciousProbability,
        classification: stored.classification as JevDecision["classification"],
        severityScore: stored.severityScore,
        confidence: stored.confidence,
        noul: stored.noul ?? "",
        choice: stored.choice ?? "",
        score: stored.score ?? "",
        evidence: stored.evidence ?? [],
        source: stored.source as JevDecision["source"],
        latencyMs: stored.latencyMs,
      }
    : undefined;

  const gemini: GeminiInvestigation | undefined = investigation
    ? {
        summary: investigation.summary,
        classification: investigation.classification,
        rootCause: investigation.rootCause,
        evidence: investigation.evidence ?? [],
        mitre: (investigation.mitre ?? []).map((item) => ({
          id: item.id ?? "—",
          tactic: item.tactic ?? "Under review",
          technique: item.technique ?? "Not yet classified",
        })),
        impact: investigation.impact,
        risks: (investigation.risks ?? []).map((risk) => ({
          label: risk.label ?? "Unlabelled",
          score: Number(risk.score ?? 0),
        })),
        recommendedAction: investigation.recommendedAction as GeminiInvestigation["recommendedAction"],
        containment: investigation.containment,
        remediation: investigation.remediation,
        confidenceExplanation: investigation.confidenceExplanation,
        alternatives: (investigation.alternatives ?? []).map((alt) => ({
          action: (alt.action ?? "HUMAN REVIEW") as GeminiInvestigation["recommendedAction"],
          note: alt.note ?? "",
          viability: Number(alt.viability ?? 50),
        })),
        remediationCode: investigation.remediationCode,
        remediationLanguage: investigation.remediationLanguage as GeminiInvestigation["remediationLanguage"],
        source: investigation.source as GeminiInvestigation["source"],
        latencyMs: investigation.latencyMs,
      }
    : undefined;

  return runCore(event, {
    jev,
    gemini,
    reviewStatus: doc.status as TriageResult["reviewStatus"],
  });
}

export { toTriageEvent };
