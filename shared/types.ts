/**
 * CyberSentinel v2.0 — shared domain model.
 *
 * Deliberately free of React, DOM and Node imports so it can be consumed by the
 * Vite frontend (via `src/core`) and by the Express backend (via `backend/src`).
 * One copy of the domain vocabulary keeps the queue UI, the deep-dive drawer and
 * the REST responses in agreement.
 */

/** Attack classes the fast model is allowed to emit. */
export type ThreatType =
  | "SQL Injection"
  | "Prompt Injection"
  | "Ransomware Signature"
  | "Credential Attack"
  | "Insider Threat"
  | "Data Exfiltration"
  | "Malware"
  | "Privilege Escalation"
  | "Benign Anomaly"
  | "Unknown / Other";

export const THREAT_TYPES: ThreatType[] = [
  "SQL Injection",
  "Prompt Injection",
  "Ransomware Signature",
  "Credential Attack",
  "Insider Threat",
  "Data Exfiltration",
  "Malware",
  "Privilege Escalation",
  "Benign Anomaly",
  "Unknown / Other",
];

/** Simulated response actions the Decision Engine ranks. */
export type ActionKind =
  | "BLOCK"
  | "ISOLATE"
  | "QUARANTINE"
  | "THROTTLE"
  | "ALLOW"
  | "HUMAN REVIEW";

export const ACTION_KINDS: ActionKind[] = [
  "BLOCK",
  "ISOLATE",
  "QUARANTINE",
  "THROTTLE",
  "ALLOW",
  "HUMAN REVIEW",
];

/** Where the probability landed, and therefore how the event is routed. */
export type RouteKind = "CONTAIN" | "GRAY" | "DISMISS";

/** Lifecycle of an event once it is on the analyst's desk. */
export type ReviewStatus = "PENDING" | "APPROVED" | "OVERRIDDEN" | "DISMISSED";

/** Which engine produced the numbers on screen. Never blurred in the UI. */
export type AiMode = "LIVE" | "DEMO_FIXTURE";

/** Simulated host lifecycle. Containment only ever mutates this field. */
export type ServerStatus =
  | "ONLINE"
  | "MONITORING"
  | "THROTTLED"
  | "INVESTIGATING"
  | "ISOLATED"
  | "COMPROMISED";

/**
 * What kind of asset the event is riding on. Drives how much each action
 * actually contains: a request-level payload is stopped by BLOCK, whereas a
 * host-level payload needs ISOLATE.
 */
export type EventScope = "request" | "host" | "identity" | "data" | "anomaly";

export interface SimServer {
  serverId: string;
  hostname: string;
  region: string;
  os: string;
  status: ServerStatus;
  threatScore: number;
  criticality: number;
  cpu: number;
  network: number;
  lastEventAt: number | null;
}

export interface SecurityEvent {
  id: string;
  timestamp: number;
  serverId: string;
  /** Raw signal name, e.g. `prompt_injection`. */
  eventType: string;
  payload: string;
  source: string;
  user?: string;
  networkContext?: string;
  scope: EventScope;
  /** 1..10 */
  assetCriticality: number;
  /** 1..10 */
  dataSensitivity: number;
}

/**
 * Result of the fast first pass ("System 1"). Three typed questions are asked:
 * Noul (probability), Choice (classification), Score (blast radius).
 */
export interface JevDecision {
  maliciousProbability: number;
  classification: ThreatType;
  /** 1..10 */
  severityScore: number;
  /** Certainty that the classification is right, 0..1. */
  confidence: number;
  noul: string;
  choice: string;
  score: string;
  evidence: string[];
  source: AiMode;
  latencyMs: number;
}

export interface MitreReference {
  id: string;
  tactic: string;
  technique: string;
}

export interface RiskFactor {
  label: string;
  /** 0..100 */
  score: number;
}

export interface AlternativeAction {
  action: ActionKind;
  note: string;
  /** 0..100 — how plausible this alternative is under current factors. */
  viability: number;
}

/** Structured forensic report returned by the deep model ("System 2"). */
export interface GeminiInvestigation {
  summary: string;
  classification: string;
  rootCause: string;
  evidence: string[];
  mitre: MitreReference[];
  impact: string;
  risks: RiskFactor[];
  recommendedAction: ActionKind;
  containment: string;
  remediation: string;
  confidenceExplanation: string;
  alternatives: AlternativeAction[];
  /** Always labelled in the UI — never auto-executed. */
  remediationCode: string;
  remediationLanguage: "bash" | "powershell";
  source: AiMode | "UNAVAILABLE";
  latencyMs: number;
  error?: string;
}

/** The nine factors the Decision Engine weighs, all normalised 0..100. */
export interface DecisionFactors {
  threatProbability: number;
  /** 1..10 */
  severity: number;
  assetCriticality: number;
  dataSensitivity: number;
  businessImpact: number;
  securitySensitivity: number;
  riskTolerance: number;
  availabilityPriority: number;
  automationLevel: number;
}

export interface ScoredAction {
  action: ActionKind;
  score: number;
  /** 0..100 normalised for display. */
  normalized: number;
  containment: "High" | "Medium" | "Low" | "None";
  disruption: "High" | "Medium" | "Low" | "Minimal";
  speed: "Very fast" | "Fast" | "Immediate" | "Slow";
  cost: "Low" | "Medium" | "High";
  exposure: "High" | "Medium" | "Low" | "None";
  selected: boolean;
}

export interface AlternativeOption {
  action: ActionKind;
  why: string;
  tradeoff: string;
  score: number;
}

export interface DecisionRecord {
  route: RouteKind;
  action: ActionKind;
  /** Why this action and not another. */
  why: string;
  /** What happens if nobody acts. */
  riskIfNotTaken: string;
  confidence: number;
  evidence: string[];
  factors: DecisionFactors;
  ranked: ScoredAction[];
  alternatives: AlternativeOption[];
}

export type TimelineTone =
  | "neutral"
  | "critical"
  | "warning"
  | "safe"
  | "ai";

export interface TimelineStep {
  key: string;
  label: string;
  detail: string;
  state: "done" | "active" | "skipped" | "failed";
  tone: TimelineTone;
  /** 0..1 when the step reports a confidence figure. */
  confidence?: number;
  latencyMs?: number;
  caption?: string;
}

export interface LatencyBreakdown {
  jevMs: number;
  geminiMs: number;
  totalMs: number;
}

/** One row of the audit trail. Append-only by construction. */
export interface AuditEntry {
  id: string;
  timestamp: number;
  actor: string;
  eventId: string;
  action: string;
  detail: string;
}

/** The complete, self-contained result of triaging one event. */
export interface TriageResult {
  event: SecurityEvent;
  jev: JevDecision;
  route: RouteKind;
  /** Set when the route was CONTAIN. */
  containment: { action: ActionKind; serverId: string; simulated: true } | null;
  /** `null` when the route was not GRAY, or when the deep model was unavailable. */
  gemini: GeminiInvestigation | null;
  decision: DecisionRecord;
  timeline: TimelineStep[];
  latency: LatencyBreakdown;
  reviewStatus: ReviewStatus;
  reviewedBy?: string;
  reviewNote?: string;
  reviewedAt?: number;
  aiMode: AiMode;
  /** True when the deep model was requested but failed. */
  escalationFailed?: boolean;
}

export interface QueueMetrics {
  ingested: number;
  contained: number;
  dismissed: number;
  grayZone: number;
  geminiCalls: number;
  geminiCallsAvoided: number;
  pendingReview: number;
  reviewed: number;
  avgTotalLatencyMs: number;
  avgJevLatencyMs: number;
}
