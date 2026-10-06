import type { ActionKind, EventScope, RouteKind, ThreatType } from "./types";

/**
 * Routing thresholds — the contract described in the spec:
 *
 *   p > 0.95        → CONTAIN  (act now, never wait for the deep model)
 *   p < 0.40        → DISMISS  (never spend a deep-model call)
 *   0.40 ≤ p ≤ 0.95 → GRAY     (throttle, then escalate for forensics)
 *
 * Imported by both the browser and the Express process so the UI and the API
 * can never disagree about where the boundaries sit.
 */
export const CONTAIN_THRESHOLD = 0.95;
export const DISMISS_THRESHOLD = 0.4;

export function routeForProbability(p: number): RouteKind {
  if (p > CONTAIN_THRESHOLD) return "CONTAIN";
  if (p < DISMISS_THRESHOLD) return "DISMISS";
  return "GRAY";
}

/** Human-readable reason the router gives for its choice. */
export function routeReason(p: number, route: RouteKind): string {
  if (route === "CONTAIN") {
    return `Malicious probability ${p.toFixed(2)} is above the ${CONTAIN_THRESHOLD.toFixed(2)} containment threshold — act immediately, do not wait for deep analysis.`;
  }
  if (route === "DISMISS") {
    return `Malicious probability ${p.toFixed(2)} is below the ${DISMISS_THRESHOLD.toFixed(2)} dismissal threshold — the event is most likely benign, so no deep-model call is spent.`;
  }
  return `Malicious probability ${p.toFixed(2)} sits inside the ${DISMISS_THRESHOLD.toFixed(2)}–${CONTAIN_THRESHOLD.toFixed(2)} ambiguity band — neither containment nor dismissal is safe, so the event is escalated for forensics.`;
}

/**
 * How much of the threat each simulated action actually contains, per asset
 * scope. Blocking a request stops a SQL injection cold but does nothing for
 * ransomware already running on a host; isolation is the reverse.
 */
export const CONTAINMENT_BY_SCOPE: Record<
  EventScope,
  Record<ActionKind, number>
> = {
  request: {
    BLOCK: 0.95,
    ISOLATE: 1.0,
    QUARANTINE: 0.7,
    THROTTLE: 0.45,
    ALLOW: 0,
    "HUMAN REVIEW": 0.5,
  },
  host: {
    BLOCK: 0.45,
    ISOLATE: 1.0,
    QUARANTINE: 0.75,
    THROTTLE: 0.3,
    ALLOW: 0,
    "HUMAN REVIEW": 0.5,
  },
  identity: {
    BLOCK: 0.9,
    ISOLATE: 1.0,
    QUARANTINE: 0.7,
    THROTTLE: 0.4,
    ALLOW: 0,
    "HUMAN REVIEW": 0.5,
  },
  data: {
    BLOCK: 0.7,
    ISOLATE: 0.95,
    QUARANTINE: 0.8,
    THROTTLE: 0.5,
    ALLOW: 0,
    "HUMAN REVIEW": 0.5,
  },
  anomaly: {
    BLOCK: 0.6,
    ISOLATE: 0.9,
    QUARANTINE: 0.7,
    THROTTLE: 0.45,
    ALLOW: 0,
    "HUMAN REVIEW": 0.5,
  },
};

/** Operational disruption each action causes, 0..1. */
export const DISRUPTION: Record<ActionKind, number> = {
  BLOCK: 0.35,
  ISOLATE: 1.0,
  QUARANTINE: 0.6,
  THROTTLE: 0.2,
  ALLOW: 0.05,
  "HUMAN REVIEW": 0.5,
};

/** How much damage a wrong call of this action does, 0..1. */
export const FALSE_POSITIVE_EXPOSURE: Record<ActionKind, number> = {
  ISOLATE: 1.0,
  BLOCK: 0.8,
  QUARANTINE: 0.5,
  THROTTLE: 0.3,
  ALLOW: 0.1,
  "HUMAN REVIEW": 0,
};

/** How much irreversibility / blast radius automation adds, 0..1. */
export const AUTOMATION_EXPOSURE: Record<ActionKind, number> = {
  ISOLATE: 1.0,
  BLOCK: 0.8,
  QUARANTINE: 0.6,
  THROTTLE: 0.4,
  ALLOW: 0.2,
  "HUMAN REVIEW": 0,
};

/** Which actions are even eligible on each route. */
export const ROUTE_CANDIDATES: Record<RouteKind, ActionKind[]> = {
  CONTAIN: ["BLOCK", "ISOLATE", "QUARANTINE"],
  GRAY: ["THROTTLE", "QUARANTINE", "BLOCK", "HUMAN REVIEW", "ALLOW"],
  DISMISS: ["ALLOW", "THROTTLE", "HUMAN REVIEW"],
};

/** Default analyst posture — all 0..100. */
export const DEFAULT_PREFERENCES = {
  securitySensitivity: 70,
  riskTolerance: 35,
  availabilityPriority: 55,
  businessContinuity: 60,
  dataProtection: 75,
  automationLevel: 65,
} as const;

export type Preferences = {
  -readonly [K in keyof typeof DEFAULT_PREFERENCES]: number;
};

/** Display metadata for the decision matrix. */
export const ACTION_PROFILE: Record<
  ActionKind,
  {
    containment: ScoredActionLabels["containment"];
    disruption: ScoredActionLabels["disruption"];
    speed: ScoredActionLabels["speed"];
    cost: ScoredActionLabels["cost"];
    exposure: ScoredActionLabels["exposure"];
    short: string;
  }
> = {
  BLOCK: {
    containment: "High",
    disruption: "Medium",
    speed: "Very fast",
    cost: "Low",
    exposure: "Low",
    short: "Deny the offending request at the edge.",
  },
  ISOLATE: {
    containment: "High",
    disruption: "High",
    speed: "Fast",
    cost: "Medium",
    exposure: "None",
    short: "Cut the host off from the network (simulated).",
  },
  QUARANTINE: {
    containment: "Medium",
    disruption: "Low",
    speed: "Fast",
    cost: "Low",
    exposure: "Medium",
    short: "Park the workload, keep it observable.",
  },
  THROTTLE: {
    containment: "Medium",
    disruption: "Low",
    speed: "Immediate",
    cost: "Low",
    exposure: "Medium",
    short: "Rate-limit while evidence is gathered.",
  },
  ALLOW: {
    containment: "None",
    disruption: "Minimal",
    speed: "Immediate",
    cost: "Low",
    exposure: "High",
    short: "Let it through and keep watching.",
  },
  "HUMAN REVIEW": {
    containment: "Low",
    disruption: "Medium",
    speed: "Slow",
    cost: "Medium",
    exposure: "Low",
    short: "Hand the decision to an analyst.",
  },
};

interface ScoredActionLabels {
  containment: "High" | "Medium" | "Low" | "None";
  disruption: "High" | "Medium" | "Low" | "Minimal";
  speed: "Very fast" | "Fast" | "Immediate" | "Slow";
  cost: "Low" | "Medium" | "High";
  exposure: "High" | "Medium" | "Low" | "None";
}

/** MITRE ATT&CK references used by the forensic report (simulated mapping). */
export const MITRE_MAP: Record<ThreatType, { id: string; tactic: string; technique: string }[]> = {
  "SQL Injection": [
    { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
    { id: "T1505", tactic: "Persistence", technique: "Server Software Component" },
  ],
  "Prompt Injection": [
    { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" },
    { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
  ],
  "Ransomware Signature": [
    { id: "T1486", tactic: "Impact", technique: "Data Encrypted for Impact" },
    { id: "T1490", tactic: "Impact", technique: "Inhibit System Recovery" },
  ],
  "Credential Attack": [
    { id: "T1110", tactic: "Credential Access", technique: "Brute Force" },
    { id: "T1552", tactic: "Credential Access", technique: "Unsecured Credentials" },
  ],
  "Insider Threat": [
    { id: "T1530", tactic: "Collection", technique: "Data from Cloud Storage Object" },
    { id: "T1537", tactic: "Exfiltration", technique: "Transfer Data to Cloud Account" },
  ],
  "Data Exfiltration": [
    { id: "T1041", tactic: "Exfiltration", technique: "Exfiltration Over C2 Channel" },
    { id: "T1567", tactic: "Exfiltration", technique: "Exfiltration Over Web Service" },
  ],
  Malware: [
    { id: "T1204.002", tactic: "Execution", technique: "Malicious File" },
    { id: "T1204", tactic: "Execution", technique: "User Execution" },
  ],
  "Privilege Escalation": [
    { id: "T1068", tactic: "Privilege Escalation", technique: "Exploitation for Privilege Escalation" },
    { id: "T1548", tactic: "Privilege Escalation", technique: "Abuse Elevation Control Mechanism" },
  ],
  "Benign Anomaly": [{ id: "—", tactic: "None", technique: "No adversarial technique identified" }],
  "Unknown / Other": [
    { id: "T1078", tactic: "Initial Access", technique: "Valid Accounts" },
    { id: "—", tactic: "Under review", technique: "Technique not yet classified" },
  ],
};

/** Risk vocabulary surfaced on every deep dive. */
export const RISK_LABELS = [
  "Data leakage",
  "Privacy exposure",
  "Credential compromise",
  "Lateral movement",
  "System compromise",
  "Financial impact",
  "Reputation impact",
] as const;
