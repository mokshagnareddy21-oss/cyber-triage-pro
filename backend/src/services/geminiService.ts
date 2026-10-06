import { env, hasGeminiKey } from "../env";
import { geminiFixture, geminiUnavailable } from "../../../shared/fixtures";
import { extractJson, completionText } from "./jevService";
import { z } from "zod";
import type {
  ActionKind,
  GeminiInvestigation,
  JevDecision,
  SecurityEvent,
} from "../../../shared/types";

/**
 * Gemini / System Two — deep forensic reasoning.
 *
 * Only ever invoked for gray-zone events (or on explicit analyst request).
 * Contract (spec §33):
 *  - GEMINI_API_KEY and GEMINI_MODEL come from the environment
 *  - structured prompt, fixed JSON schema
 *  - response validated before it reaches the UI
 *  - malformed responses handled gracefully
 *  - the API key never leaves this process
 *
 * No key configured → deterministic DEMO FIXTURE.
 * Key configured but the call fails → UNAVAILABLE, which the UI renders as
 * "GEMINI UNAVAILABLE" and resolves to HUMAN REVIEW REQUIRED.
 */

const ACTIONS = ["BLOCK", "ISOLATE", "QUARANTINE", "THROTTLE", "ALLOW", "HUMAN REVIEW"] as const;

const InvestigationSchema = z.object({
  summary: z.string().min(1),
  classification: z.string().min(1),
  rootCause: z.string().min(1),
  evidence: z.array(z.string()).default([]),
  mitre: z
    .array(
      z.object({
        id: z.string().default("—"),
        tactic: z.string().default("Under review"),
        technique: z.string().default("Not yet classified"),
      }),
    )
    .default([]),
  impact: z.string().default(""),
  risks: z
    .array(z.object({ label: z.string(), score: z.number().min(0).max(100) }))
    .default([]),
  recommendedAction: z.enum(ACTIONS).default("HUMAN REVIEW"),
  containment: z.string().default(""),
  remediation: z.string().default(""),
  confidenceExplanation: z.string().default(""),
  alternatives: z
    .array(
      z.object({
        action: z.enum(ACTIONS),
        note: z.string().default(""),
        viability: z.number().min(0).max(100).default(50),
      }),
    )
    .default([]),
  remediationCode: z.string().default(""),
  remediationLanguage: z.enum(["bash", "powershell"]).default("bash"),
});

export type Investigation = z.infer<typeof InvestigationSchema>;

export interface GeminiResult {
  investigation: GeminiInvestigation;
  raw: string;
}

const SYSTEM_PROMPT = [
  "You are a senior SOC forensic analyst working inside an automated triage pipeline.",
  "You receive one security event together with the fast model's probability,",
  "classification and severity. Decide whether the event is hostile and what the",
  "SOC should do about it.",
  "",
  "Return ONLY valid JSON matching this schema:",
  "{",
  '  "summary": string,',
  '  "classification": string,',
  '  "rootCause": string,',
  '  "evidence": string[],',
  '  "mitre": [{"id": string, "tactic": string, "technique": string}],',
  '  "impact": string,',
  '  "risks": [{"label": string, "score": number}],  // score 0-100',
  '  "recommendedAction": "BLOCK" | "ISOLATE" | "QUARANTINE" | "THROTTLE" | "ALLOW" | "HUMAN REVIEW",',
  '  "containment": string,',
  '  "remediation": string,',
  '  "confidenceExplanation": string,',
  '  "alternatives": [{"action": string, "note": string, "viability": number}],',
  '  "remediationCode": string,   // bash or powershell, or "" if none',
  '  "remediationLanguage": "bash" | "powershell"',
  "}",
  "Risk labels must be drawn from: Data leakage, Privacy exposure, Credential",
  "compromise, Lateral movement, System compromise, Financial impact, Reputation impact.",
  "Never invent infrastructure you were not given. Never claim to have executed anything.",
].join("\n");

function buildUserPrompt(event: SecurityEvent, jev: JevDecision): string {
  return JSON.stringify(
    {
      event: {
        id: event.id,
        serverId: event.serverId,
        source: event.source,
        eventType: event.eventType,
        payload: event.payload,
        user: event.user ?? null,
        networkContext: event.networkContext ?? null,
        assetCriticality: event.assetCriticality,
        dataSensitivity: event.dataSensitivity,
        scope: event.scope,
      },
      fastModel: {
        maliciousProbability: jev.maliciousProbability,
        classification: jev.classification,
        severity: jev.severityScore,
        confidence: jev.confidence,
        evidence: jev.evidence,
      },
      note: "Simulated demo environment. All infrastructure is synthetic.",
    },
    null,
    2,
  );
}

function normalise(parsed: Investigation, latencyMs: number): GeminiInvestigation {
  return {
    summary: parsed.summary,
    classification: parsed.classification,
    rootCause: parsed.rootCause,
    evidence: parsed.evidence,
    mitre: parsed.mitre,
    impact: parsed.impact,
    risks: [...parsed.risks].sort((a, b) => b.score - a.score),
    recommendedAction: parsed.recommendedAction as ActionKind,
    containment: parsed.containment,
    remediation: parsed.remediation,
    confidenceExplanation: parsed.confidenceExplanation,
    alternatives: parsed.alternatives.filter(
      (entry) => entry.action !== parsed.recommendedAction,
    ),
    remediationCode: parsed.remediationCode,
    remediationLanguage: parsed.remediationLanguage,
    source: "LIVE",
    latencyMs,
  };
}

/** Escalate a gray-zone event to Gemini. */
export async function runGemini(
  event: SecurityEvent,
  jev: JevDecision,
): Promise<GeminiResult> {
  const fixture = geminiFixture({ event, jev });

  if (!hasGeminiKey()) {
    return { investigation: fixture, raw: JSON.stringify({ mode: "DEMO_FIXTURE" }) };
  }

  const startedAt = Date.now();
  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
      env.GEMINI_MODEL,
    )}:generateContent`;

    const response = await fetch(`${endpoint}?key=${encodeURIComponent(env.GEMINI_API_KEY)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
        contents: [{ role: "user", parts: [{ text: buildUserPrompt(event, jev) }] }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: "application/json",
        },
      }),
      signal: AbortSignal.timeout(20000),
    });

    const latencyMs = Date.now() - startedAt;
    if (!response.ok) throw new Error(`Gemini responded with status ${response.status}`);

    const payload: unknown = await response.json();
    const parsed = InvestigationSchema.safeParse(extractJson(completionText(payload)));
    if (!parsed.success) {
      throw new Error("Gemini returned JSON that did not match the forensic schema.");
    }

    return { investigation: normalise(parsed.data, latencyMs), raw: JSON.stringify(payload) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown Gemini failure";
    console.warn(`[gemini] escalation failed — ${message}`);
    return {
      investigation: geminiUnavailable(message),
      raw: JSON.stringify({ error: message }),
    };
  }
}
