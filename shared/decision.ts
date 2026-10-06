import {
  ACTION_PROFILE,
  AUTOMATION_EXPOSURE,
  CONTAINMENT_BY_SCOPE,
  CONTAIN_THRESHOLD,
  DISMISS_THRESHOLD,
  DISRUPTION,
  FALSE_POSITIVE_EXPOSURE,
  MITRE_MAP,
  RISK_LABELS,
  ROUTE_CANDIDATES,
  routeReason,
} from "./thresholds";
import type {
  ActionKind,
  AlternativeOption,
  DecisionFactors,
  DecisionRecord,
  GeminiInvestigation,
  JevDecision,
  LatencyBreakdown,
  MitreReference,
  RiskFactor,
  ScoredAction,
  SecurityEvent,
  TimelineStep,
  ThreatType,
} from "./types";

export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/* ------------------------------------------------------------------ *
 * Confidence
 * ------------------------------------------------------------------ */

/**
 * Certainty that the fast model's *label* is right. A probability of 0.99
 * means 99% confidence in "malicious"; 0.12 means 88% confidence in
 * "benign"; 0.73 means only 73% confidence in anything — which is exactly why
 * the middle band escalates instead of acting.
 */
export function classificationConfidence(p: number): number {
  return clamp(Math.max(p, 1 - p), 0, 1);
}

/**
 * Certainty that *routing* the event this way was correct: how much margin the
 * probability has against the threshold it was judged by. Deep inside the
 * ambiguity band the margin collapses, which is exactly why we escalate.
 */
export function routeConfidence(p: number, route: "CONTAIN" | "GRAY" | "DISMISS"): number {
  if (route === "CONTAIN") return clamp(0.9 + ((p - CONTAIN_THRESHOLD) / 0.05) * 0.09, 0.9, 0.99);
  if (route === "DISMISS") {
    return clamp(0.9 + ((DISMISS_THRESHOLD - p) / DISMISS_THRESHOLD) * 0.09, 0.85, 0.97);
  }
  const dist = Math.min(p - DISMISS_THRESHOLD, CONTAIN_THRESHOLD - p);
  return clamp(0.62 + (1 - dist / 0.275) * 0.16, 0.6, 0.78);
}

/* ------------------------------------------------------------------ *
 * Action scoring
 * ------------------------------------------------------------------ */

export interface ScoreInput {
  event: SecurityEvent;
  jev: JevDecision;
  route: "CONTAIN" | "GRAY" | "DISMISS";
  preferences: {
    securitySensitivity: number;
    riskTolerance: number;
    availabilityPriority: number;
    businessContinuity: number;
    dataProtection: number;
    automationLevel: number;
  };
}

/**
 * Multi-criteria utility score for one simulated response action.
 *
 *   + captured threat value, scaled by security posture
 *   − residual threat left behind, scaled by risk tolerance & data protection
 *   − operational disruption, scaled by availability & continuity priorities
 *   − false-positive exposure, scaled by model confidence
 *   − automation exposure, scaled by how much automation the analyst wants
 *
 * Everything is 0..100 normalised, so the result is comparable across actions
 * and explainable in the UI: each term maps to a line in the "why" copy.
 */
export function scoreAction(action: ActionKind, input: ScoreInput): number {
  const { event, jev, preferences } = input;
  const probability = jev.maliciousProbability;
  const severity = clamp(jev.severityScore, 1, 10) / 10;
  const threat = probability * severity;
  const stops = CONTAINMENT_BY_SCOPE[event.scope][action];
  const residual = 1 - stops;

  const securityGain = 0.7 + 0.6 * (preferences.securitySensitivity / 100);
  const residualWeight =
    (1 - preferences.riskTolerance / 100) * (0.5 + 0.5 * (preferences.dataProtection / 100));
  const disruptionWeight =
    0.3 +
    0.7 *
      ((preferences.availabilityPriority * 0.6 +
        preferences.businessContinuity * 0.4) /
        100);
  const falsePositiveWeight = (1 - jev.confidence) * (0.4 + 0.6 * 0.5);
  const automationWeight = (1 - preferences.automationLevel / 100) * 0.3;

  const captured = threat * stops * securityGain;
  const residualLoss = threat * residual * residualWeight;
  const disruption = DISRUPTION[action] * disruptionWeight;
  const falsePositive = FALSE_POSITIVE_EXPOSURE[action] * falsePositiveWeight;
  const automation = AUTOMATION_EXPOSURE[action] * automationWeight;

  return captured - residualLoss - disruption - falsePositive - automation;
}

function normalizeScore(score: number): number {
  return Math.round(clamp(50 + score * 60, 3, 99));
}

export function rankActions(input: ScoreInput): ScoredAction[] {
  const candidates = ROUTE_CANDIDATES[input.route];
  const scored: ScoredAction[] = candidates.map((action) => {
    const score = scoreAction(action, input);
    const profile = ACTION_PROFILE[action];
    return {
      action,
      score,
      normalized: normalizeScore(score),
      containment: profile.containment,
      disruption: profile.disruption,
      speed: profile.speed,
      cost: profile.cost,
      exposure: profile.exposure,
      selected: false,
    };
  });
  scored.sort((a, b) => b.score - a.score);
  if (scored.length > 0) scored[0] = { ...scored[0], selected: true };
  return scored;
}

/* ------------------------------------------------------------------ *
 * Explanations
 * ------------------------------------------------------------------ */

const SCOPE_NOUN: Record<string, string> = {
  request: "a request-scoped payload",
  host: "a host-scoped payload",
  identity: "an identity-scoped attempt",
  data: "a data-handling anomaly",
  anomaly: "a behavioural anomaly",
};

function buildWhy(input: ScoreInput, action: ActionKind, ranked: ScoredAction[]): string {
  const { event, jev, preferences } = input;
  const stops = Math.round(CONTAINMENT_BY_SCOPE[event.scope][action] * 100);
  const runnerUp = ranked[1];
  const gap = runnerUp ? (ranked[0].score - runnerUp.score).toFixed(2) : null;
  const basis =
    action === "ALLOW"
      ? `malicious probability ${jev.maliciousProbability.toFixed(2)} leaves too little expected impact to justify disruption`
      : `it contains roughly ${stops}% of ${SCOPE_NOUN[event.scope]} at probability ${jev.maliciousProbability.toFixed(2)} and severity ${jev.severityScore}/10`;
  const posture = `Posture: security sensitivity ${preferences.securitySensitivity}, risk tolerance ${preferences.riskTolerance}, availability priority ${preferences.availabilityPriority}, data protection ${preferences.dataProtection} (0–100).`;
  const margin = gap ? ` It scores ${gap} above the next-best eligible action.` : "";
  return `${action} is selected because ${basis}.${margin} ${posture}`;
}

function buildRisk(input: ScoreInput, action: ActionKind): string {
  const { event, jev } = input;
  const residual = Math.round((1 - CONTAINMENT_BY_SCOPE[event.scope][action]) * 100);
  const blast = Math.round(jev.maliciousProbability * jev.severityScore * 10);
  if (action === "ALLOW") {
    return `Doing nothing leaves ${blast}% of the blast radius live. On ${event.serverId} (criticality ${event.assetCriticality}/10) that means a ${jev.classification.toLowerCase()} condition could progress to data leakage, credential exposure and lateral movement before anyone notices.`;
  }
  return `Without ${action}, roughly ${residual}% of the threat survives containment. Given a severity of ${jev.severityScore}/10 on ${event.serverId}, the residual path is ${jev.classification.toLowerCase()} → follow-on access → wider compromise.`;
}

function buildAlternatives(ranked: ScoredAction[], selected: ActionKind): AlternativeOption[] {
  return ranked
    .filter((entry) => entry.action !== selected)
    .map((entry) => ({
      action: entry.action,
      why: `${ACTION_PROFILE[entry.action].short} Scores ${entry.normalized}/100 under the current posture.`,
      tradeoff: `${entry.containment} containment · ${entry.disruption} disruption · ${entry.speed.toLowerCase()} to apply · ${entry.exposure.toLowerCase()} residual exposure.`,
      score: entry.score,
    }));
}

export function evidenceFor(input: ScoreInput): string[] {
  const { event, jev, preferences } = input;
  const evidence = [
    `Noul · malicious probability ${jev.maliciousProbability.toFixed(2)} (${jev.source === "LIVE" ? "live model" : "DEMO FIXTURE"})`,
    `Choice · ${jev.classification}`,
    `Score · blast radius ${jev.severityScore}/10`,
    `Asset criticality ${event.assetCriticality}/10 on ${event.serverId}`,
    `Data sensitivity ${event.dataSensitivity}/10`,
    ...jev.evidence.map((line) => `Signal · ${line}`),
    `Posture · security sensitivity ${preferences.securitySensitivity} / risk tolerance ${preferences.riskTolerance} / automation ${preferences.automationLevel}`,
  ];
  return evidence;
}

export function buildDecision(input: ScoreInput, override?: ActionKind): DecisionRecord {
  const ranked = rankActions(input);
  const action = override ?? ranked[0]?.action ?? "HUMAN REVIEW";
  const runnerUp = ranked.find((entry) => entry.action !== action);
  const top = ranked.find((entry) => entry.action === action);
  const margin = top && runnerUp ? top.score - runnerUp.score : 0.4;
  const confidence = clamp(0.55 + margin * 2.5, 0.5, 0.98);

  return {
    route: input.route,
    action,
    why: buildWhy(input, action, ranked),
    riskIfNotTaken: buildRisk(input, action),
    confidence,
    evidence: evidenceFor(input),
    factors: factorSnapshot(input),
    ranked,
    alternatives: buildAlternatives(ranked, action),
  };
}

export function factorSnapshot(input: ScoreInput): DecisionFactors {
  const { event, jev, preferences } = input;
  return {
    threatProbability: Math.round(jev.maliciousProbability * 100),
    severity: jev.severityScore,
    assetCriticality: event.assetCriticality,
    dataSensitivity: event.dataSensitivity,
    businessImpact: Math.round(
      clamp(
        (event.assetCriticality * 0.6 + jev.severityScore * 0.4) * 10,
        0,
        100,
      ),
    ),
    securitySensitivity: preferences.securitySensitivity,
    riskTolerance: preferences.riskTolerance,
    availabilityPriority: preferences.availabilityPriority,
    automationLevel: preferences.automationLevel,
  };
}

/* ------------------------------------------------------------------ *
 * Risk + MITRE
 * ------------------------------------------------------------------ */

const RISK_WEIGHTS: Record<ThreatType, Record<string, number>> = {
  "SQL Injection": {
    "Data leakage": 0.9,
    "Privacy exposure": 0.7,
    "Credential compromise": 0.5,
    "Lateral movement": 0.35,
    "System compromise": 0.6,
    "Financial impact": 0.6,
    "Reputation impact": 0.7,
  },
  "Prompt Injection": {
    "Data leakage": 0.85,
    "Privacy exposure": 0.75,
    "Credential compromise": 0.8,
    "Lateral movement": 0.3,
    "System compromise": 0.55,
    "Financial impact": 0.5,
    "Reputation impact": 0.75,
  },
  "Ransomware Signature": {
    "Data leakage": 0.6,
    "Privacy exposure": 0.4,
    "Credential compromise": 0.7,
    "Lateral movement": 0.85,
    "System compromise": 1,
    "Financial impact": 0.95,
    "Reputation impact": 0.9,
  },
  "Credential Attack": {
    "Data leakage": 0.7,
    "Privacy exposure": 0.6,
    "Credential compromise": 1,
    "Lateral movement": 0.8,
    "System compromise": 0.7,
    "Financial impact": 0.7,
    "Reputation impact": 0.7,
  },
  "Insider Threat": {
    "Data leakage": 0.95,
    "Privacy exposure": 0.9,
    "Credential compromise": 0.5,
    "Lateral movement": 0.3,
    "System compromise": 0.45,
    "Financial impact": 0.7,
    "Reputation impact": 0.85,
  },
  "Data Exfiltration": {
    "Data leakage": 1,
    "Privacy exposure": 0.85,
    "Credential compromise": 0.45,
    "Lateral movement": 0.4,
    "System compromise": 0.5,
    "Financial impact": 0.75,
    "Reputation impact": 0.8,
  },
  Malware: {
    "Data leakage": 0.65,
    "Privacy exposure": 0.5,
    "Credential compromise": 0.7,
    "Lateral movement": 0.75,
    "System compromise": 0.9,
    "Financial impact": 0.7,
    "Reputation impact": 0.75,
  },
  "Privilege Escalation": {
    "Data leakage": 0.6,
    "Privacy exposure": 0.5,
    "Credential compromise": 0.85,
    "Lateral movement": 0.8,
    "System compromise": 0.9,
    "Financial impact": 0.65,
    "Reputation impact": 0.7,
  },
  "Benign Anomaly": {
    "Data leakage": 0.08,
    "Privacy exposure": 0.08,
    "Credential compromise": 0.05,
    "Lateral movement": 0.05,
    "System compromise": 0.08,
    "Financial impact": 0.1,
    "Reputation impact": 0.1,
  },
  "Unknown / Other": {
    "Data leakage": 0.55,
    "Privacy exposure": 0.5,
    "Credential compromise": 0.55,
    "Lateral movement": 0.5,
    "System compromise": 0.55,
    "Financial impact": 0.5,
    "Reputation impact": 0.5,
  },
};

export function riskFactorsFor(jev: JevDecision): RiskFactor[] {
  const base = jev.maliciousProbability * (jev.severityScore / 10);
  const weights = RISK_WEIGHTS[jev.classification] ?? RISK_WEIGHTS["Unknown / Other"];
  return RISK_LABELS.map((label) => ({
    label,
    score: Math.round(clamp(base * (0.4 + 0.6 * weights[label]) * 100, 3, 99)),
  })).sort((a, b) => b.score - a.score);
}

export function mitreFor(classification: ThreatType): MitreReference[] {
  return MITRE_MAP[classification] ?? MITRE_MAP["Unknown / Other"];
}

/* ------------------------------------------------------------------ *
 * Decision timeline
 * ------------------------------------------------------------------ */

export interface TimelineInput {
  event: SecurityEvent;
  jev: JevDecision;
  route: "CONTAIN" | "GRAY" | "DISMISS";
  containment: { action: ActionKind; serverId: string } | null;
  gemini: GeminiInvestigation | null;
  decision: DecisionRecord;
  latency: LatencyBreakdown;
  escalationFailed?: boolean;
  reviewStatus?: "PENDING" | "APPROVED" | "OVERRIDDEN" | "DISMISSED";
}

export function buildTimeline(input: TimelineInput): TimelineStep[] {
  const { event, jev, route, gemini, decision, latency, escalationFailed } = input;
  const steps: TimelineStep[] = [
    {
      key: "ingest",
      label: "Event ingested",
      detail: `${event.source} → ${event.serverId} · ${event.eventType}`,
      state: "done",
      tone: "neutral",
      caption: `${new Date(event.timestamp).toISOString()}`,
    },
    {
      key: "jev",
      label: "Jev triage · System 1",
      detail: `Noul ${jev.maliciousProbability.toFixed(2)} · Choice ${jev.classification} · Score ${jev.severityScore}/10`,
      state: "done",
      tone: jev.maliciousProbability > CONTAIN_THRESHOLD ? "critical" : route === "DISMISS" ? "safe" : "warning",
      confidence: jev.confidence,
      latencyMs: latency.jevMs,
      caption: jev.source === "LIVE" ? "LIVE MODEL" : "DEMO FIXTURE",
    },
    {
      key: "route",
      label: "Probability threshold",
      detail: routeReason(jev.maliciousProbability, route),
      state: "done",
      tone: route === "CONTAIN" ? "critical" : route === "DISMISS" ? "safe" : "warning",
      confidence: routeConfidence(jev.maliciousProbability, route),
      caption: route,
    },
  ];

  if (route === "CONTAIN") {
    steps.push({
      key: "containment",
      label: "Automated containment",
      detail: `${decision.action}(${event.serverId}) executed as a simulated state change — no real infrastructure is touched.`,
      state: "done",
      tone: "critical",
      confidence: decision.confidence,
      latencyMs: Math.max(1, Math.round(latency.jevMs * 0.15)),
      caption: "SIMULATED ACTION",
    });
    steps.push({
      key: "deep",
      label: "Deep analysis skipped",
      detail: `Confidence already above ${CONTAIN_THRESHOLD.toFixed(2)} — no Gemini call is spent.`,
      state: "skipped",
      tone: "neutral",
      caption: "COST AVOIDED",
    });
  } else if (route === "DISMISS") {
    steps.push({
      key: "dismiss",
      label: "Dismissed as likely benign",
      detail: "No containment applied, event retained for audit, no deep-model call spent.",
      state: "done",
      tone: "safe",
      confidence: decision.confidence,
      caption: "FALSE POSITIVE AVOIDED",
    });
    steps.push({
      key: "deep",
      label: "Deep analysis skipped",
      detail: `Probability below ${DISMISS_THRESHOLD.toFixed(2)} — Gemini is never invoked for dismissals.`,
      state: "skipped",
      tone: "neutral",
      caption: "COST AVOIDED",
    });
  } else {
    steps.push({
      key: "throttle",
      label: "Connection throttled",
      detail: `${event.serverId} placed in a throttled state while evidence is gathered.`,
      state: "done",
      tone: "warning",
      caption: "THROTTLED",
    });
    if (escalationFailed || gemini?.source === "UNAVAILABLE") {
      steps.push({
        key: "gemini",
        label: "Gemini unavailable",
        detail:
          gemini?.error ??
          "The deep reasoning model could not be reached. Falling back to a human decision.",
        state: "failed",
        tone: "warning",
        caption: "FALLBACK",
      });
      steps.push({
        key: "fallback",
        label: "Human review required",
        detail: "Unsafe to auto-decide without forensics — escalated to an analyst.",
        state: "done",
        tone: "warning",
        confidence: decision.confidence,
      });
    } else if (gemini) {
      steps.push({
        key: "gemini",
        label: "Gemini deep forensics · System 2",
        detail: gemini.summary,
        state: "done",
        tone: "ai",
        confidence: gemini.source === "LIVE" ? 0.86 : 0.84,
        latencyMs: latency.geminiMs,
        caption: gemini.source === "LIVE" ? "LIVE MODEL" : "DEMO FIXTURE",
      });
      steps.push({
        key: "recommend",
        label: "Reconciled recommendation",
        detail: `Deep analysis recommends ${gemini.recommendedAction}; the Decision Engine scored it against ${decision.ranked.length} eligible actions.`,
        state: "done",
        tone: "neutral",
        confidence: decision.confidence,
      });
    }
  }

  steps.push({
    key: "final",
    label: "Final recommendation",
    detail: `${decision.action} — ${decision.why}`,
    state: "done",
    tone: decision.route === "CONTAIN" ? "critical" : decision.route === "DISMISS" ? "safe" : "warning",
    confidence: decision.confidence,
    latencyMs: Math.max(1, latency.totalMs - latency.jevMs - latency.geminiMs),
    caption: `${latency.totalMs} ms total`,
  });

  if (input.reviewStatus && input.reviewStatus !== "PENDING") {
    steps.push({
      key: "review",
      label: `Analyst review · ${input.reviewStatus}`,
      detail: "Decision recorded on the immutable audit trail.",
      state: "done",
      tone: "neutral",
      caption: "HUMAN OVERSIGHT",
    });
  }

  return steps;
}

/** Cost line shown whenever Gemini was deliberately not called. */
export function savingsNote(route: "CONTAIN" | "GRAY" | "DISMISS"): string | null {
  if (route === "GRAY") return null;
  return route === "CONTAIN"
    ? "Resolved by fast triage alone — one deep-model call avoided."
    : "Dismissed below threshold — one deep-model call avoided.";
}
