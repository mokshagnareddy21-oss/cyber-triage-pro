import { Schema, model, type InferSchemaType } from "mongoose";

/**
 * Database schema (spec §30). Seven collections, all append-friendly:
 * only `Server.status` and the review fields on `SecurityEvent` are updated
 * in place — nothing in the audit or decision trails is ever rewritten.
 */

export const ROLES = ["ADMIN", "SOC_ANALYST", "VIEWER"] as const;

/* ------------------------------- User ------------------------------- */

const userSchema = new Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ROLES, default: "SOC_ANALYST" },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/* ------------------------------ Server ------------------------------ */

const serverSchema = new Schema(
  {
    serverId: { type: String, required: true, unique: true },
    hostname: { type: String, required: true },
    region: { type: String, required: true },
    os: { type: String, required: true },
    status: {
      type: String,
      enum: ["ONLINE", "MONITORING", "THROTTLED", "INVESTIGATING", "ISOLATED", "COMPROMISED"],
      default: "ONLINE",
    },
    threatScore: { type: Number, default: 0, min: 0, max: 100 },
    criticality: { type: Number, default: 5, min: 1, max: 10 },
    cpu: { type: Number, default: 20, min: 0, max: 100 },
    network: { type: Number, default: 30, min: 0, max: 100 },
    lastEventAt: { type: Date, default: null },
  },
  { timestamps: true },
);

/* --------------------------- SecurityEvent -------------------------- */

const securityEventSchema = new Schema(
  {
    eventId: { type: String, required: true, unique: true },
    timestamp: { type: Date, required: true },
    serverId: { type: String, required: true, index: true },
    eventType: { type: String, required: true },
    payload: { type: String, required: true },
    source: { type: String, required: true },
    user: { type: String },
    networkContext: { type: String },
    scope: { type: String, required: true },
    assetCriticality: { type: Number, required: true, min: 1, max: 10 },
    dataSensitivity: { type: Number, required: true, min: 1, max: 10 },

    probability: { type: Number, required: true },
    classification: { type: String, required: true },
    severity: { type: Number, required: true, min: 1, max: 10 },
    routing: { type: String, enum: ["CONTAIN", "GRAY", "DISMISS"], required: true },
    status: {
      type: String,
      enum: ["PENDING", "APPROVED", "OVERRIDDEN", "DISMISSED"],
      default: "PENDING",
    },
    reviewNote: { type: String },
    reviewedBy: { type: String },
    reviewedAt: { type: Date },

    jevLatencyMs: { type: Number, default: 0 },
    geminiLatencyMs: { type: Number, default: 0 },
    totalDecisionLatencyMs: { type: Number, default: 0 },
    simulated: { type: Boolean, default: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

securityEventSchema.index({ timestamp: -1 });

/* ---------------------------- JevDecision --------------------------- */

const jevDecisionSchema = new Schema(
  {
    eventId: { type: String, required: true, unique: true },
    maliciousProbability: { type: Number, required: true },
    classification: { type: String, required: true },
    severityScore: { type: Number, required: true },
    confidence: { type: Number, default: 0 },
    noul: { type: String },
    choice: { type: String },
    score: { type: String },
    evidence: [{ type: String }],
    source: { type: String, enum: ["LIVE", "DEMO_FIXTURE"], required: true },
    rawResponse: { type: String },
    latencyMs: { type: Number, default: 0 },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/* ------------------------ GeminiInvestigation ----------------------- */

const geminiInvestigationSchema = new Schema(
  {
    eventId: { type: String, required: true, unique: true },
    summary: { type: String, default: "" },
    classification: { type: String, default: "" },
    rootCause: { type: String, default: "" },
    evidence: [{ type: String }],
    mitre: [{ id: String, tactic: String, technique: String }],
    impact: { type: String, default: "" },
    risks: [{ label: String, score: Number }],
    recommendedAction: { type: String, default: "HUMAN REVIEW" },
    containment: { type: String, default: "" },
    remediation: { type: String, default: "" },
    confidenceExplanation: { type: String, default: "" },
    alternatives: [{ action: String, note: String, viability: Number }],
    remediationCode: { type: String, default: "" },
    remediationLanguage: { type: String, enum: ["bash", "powershell"], default: "bash" },
    source: { type: String, enum: ["LIVE", "DEMO_FIXTURE", "UNAVAILABLE"], required: true },
    rawResponse: { type: String },
    latencyMs: { type: Number, default: 0 },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/* --------------------------- DecisionRecord ------------------------- */

const decisionRecordSchema = new Schema(
  {
    eventId: { type: String, required: true, unique: true },
    route: { type: String, enum: ["CONTAIN", "GRAY", "DISMISS"], required: true },
    recommendedAction: { type: String, required: true },
    alternativeActions: [{ action: String, score: Number }],
    decisionFactors: { type: Schema.Types.Mixed, default: {} },
    riskTolerance: { type: Number, default: 35 },
    securitySensitivity: { type: Number, default: 70 },
    availabilityPriority: { type: Number, default: 55 },
    confidence: { type: Number, default: 0 },
    explanation: { type: String, default: "" },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/* ------------------------------ AuditLog ---------------------------- */

const auditLogSchema = new Schema(
  {
    timestamp: { type: Date, required: true },
    actor: { type: String, required: true },
    eventId: { type: String, index: true },
    action: { type: String, required: true },
    metadata: { type: Schema.Types.Mixed, default: {} },
    simulation: { type: Boolean, default: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

/* ------------------------------ Exports ----------------------------- */

export type UserDoc = InferSchemaType<typeof userSchema>;
export type ServerDoc = InferSchemaType<typeof serverSchema>;
export type SecurityEventDoc = InferSchemaType<typeof securityEventSchema>;

export const User = model("User", userSchema);
export const Server = model("Server", serverSchema);
export const SecurityEvent = model("SecurityEvent", securityEventSchema);
export const JevDecision = model("JevDecision", jevDecisionSchema);
export const GeminiInvestigation = model("GeminiInvestigation", geminiInvestigationSchema);
export const DecisionRecord = model("DecisionRecord", decisionRecordSchema);
export const AuditLog = model("AuditLog", auditLogSchema);
