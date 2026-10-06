import { hasJevKey, env } from "../env";
import {
  NOUL_QUESTION,
  CHOICE_QUESTION,
  SCORE_QUESTION,
  deriveJev,
} from "../../../shared/fixtures";
import { z } from "zod";
import type { JevDecision, SecurityEvent, ThreatType } from "../../../shared/types";

/**
 * Jev / System One — the fast probabilistic decision model.
 *
 * Responsibilities (spec §32):
 *  1. read JEV_API_KEY from the environment (never from the browser)
 *  2. send state plus three typed questions — Noul, Choice, Score
 *  3. parse and validate the structured response
 *  4. handle API failures without taking the dashboard down
 *  5. time the request
 *  6. return a normalised internal result
 *
 * With no key configured the service returns a deterministic fixture that is
 * labelled DEMO_FIXTURE, so the UI can never imply a live call happened.
 */

const THREAT_CLASSES = [
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
] as const;

const LiveResponseSchema = z.object({
  noul: z.union([z.number(), z.string()]).optional(),
  probability: z.union([z.number(), z.string()]).optional(),
  choice: z.string().optional(),
  classification: z.string().optional(),
  score: z.union([z.number(), z.string()]).optional(),
  severity: z.union([z.number(), z.string()]).optional(),
  confidence: z.union([z.number(), z.string()]).optional(),
  evidence: z.array(z.string()).optional(),
});

type LiveResponse = z.infer<typeof LiveResponseSchema>;

/** Pull the first JSON object out of a chat-style completion payload. */
export function extractJson(raw: string): unknown {
  const trimmed = raw.trim();
  try {
    return JSON.parse(trimmed);
  } catch {
    /* fall through to bracket matching */
  }
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) {
    try {
      return JSON.parse(trimmed.slice(start, end + 1));
    } catch {
      return null;
    }
  }
  return null;
}

/** Accept OpenAI-shaped, Gemini-shaped and bare JSON completions. */
export function completionText(payload: unknown): string {
  if (!payload || typeof payload !== "object") return "";
  const record = payload as Record<string, unknown>;

  const choices = record.choices;
  if (Array.isArray(choices) && choices[0] && typeof choices[0] === "object") {
    const message = (choices[0] as Record<string, unknown>).message;
    if (message && typeof message === "object") {
      const content = (message as Record<string, unknown>).content;
      if (typeof content === "string") return content;
    }
  }

  const candidates = record.candidates;
  if (Array.isArray(candidates) && candidates[0] && typeof candidates[0] === "object") {
    const content = (candidates[0] as Record<string, unknown>).content;
    if (content && typeof content === "object") {
      const parts = (content as Record<string, unknown>).parts;
      if (Array.isArray(parts) && parts[0] && typeof parts[0] === "object") {
        const text = (parts[0] as Record<string, unknown>).text;
        if (typeof text === "string") return text;
      }
    }
  }

  if (typeof record.output === "string") return record.output;
  return JSON.stringify(payload);
}

function toNumber(value: number | string | undefined, fallback: number): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function normalise(parsed: LiveResponse, latencyMs: number): JevDecision {
  const rawProbability = toNumber(parsed.noul ?? parsed.probability, 0.5);
  const maliciousProbability = Math.min(1, Math.max(0, rawProbability));

  const rawClass = (parsed.choice ?? parsed.classification ?? "").trim();
  const classification = (THREAT_CLASSES as readonly string[]).includes(rawClass)
    ? (rawClass as ThreatType)
    : "Unknown / Other";

  const rawSeverity = toNumber(parsed.score ?? parsed.severity, 5);
  const severityScore = Math.min(10, Math.max(1, Math.round(rawSeverity)));

  const confidenceRaw = toNumber(parsed.confidence, NaN);
  const confidence = Number.isFinite(confidenceRaw)
    ? Math.min(1, Math.max(0, confidenceRaw))
    : Math.max(maliciousProbability, 1 - maliciousProbability);

  return {
    maliciousProbability: Math.round(maliciousProbability * 100) / 100,
    classification,
    severityScore,
    confidence: Math.round(confidence * 100) / 100,
    noul: NOUL_QUESTION,
    choice: CHOICE_QUESTION,
    score: SCORE_QUESTION,
    evidence:
      parsed.evidence && parsed.evidence.length > 0
        ? parsed.evidence.slice(0, 6)
        : ["Returned by the live fast model."],
    source: "LIVE",
    latencyMs,
  };
}

export interface JevResult {
  decision: JevDecision;
  /** Raw transport payload, stored for audit. Never contains the API key. */
  raw: string;
  /** Set when a live call was attempted and failed. */
  warning?: string;
}

/** Run the three typed questions against Jev. */
export async function runJev(event: SecurityEvent): Promise<JevResult> {
  const fallback = deriveJev(event);

  if (!hasJevKey()) {
    return { decision: fallback, raw: JSON.stringify({ mode: "DEMO_FIXTURE" }) };
  }

  const startedAt = Date.now();
  try {
    const response = await fetch(env.JEV_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.JEV_API_KEY}`,
      },
      body: JSON.stringify({
        model: env.JEV_MODEL,
        state: {
          eventId: event.id,
          source: event.source,
          serverId: event.serverId,
          eventType: event.eventType,
          payload: event.payload,
          user: event.user ?? null,
          networkContext: event.networkContext ?? null,
          assetCriticality: event.assetCriticality,
          dataSensitivity: event.dataSensitivity,
          scope: event.scope,
        },
        questions: {
          noul: NOUL_QUESTION,
          choice: CHOICE_QUESTION,
          score: SCORE_QUESTION,
        },
        responseFormat: "json",
      }),
      signal: AbortSignal.timeout(9000),
    });

    const latencyMs = Date.now() - startedAt;
    if (!response.ok) {
      throw new Error(`Jev responded with status ${response.status}`);
    }

    const payload: unknown = await response.json();
    const parsed = LiveResponseSchema.safeParse(extractJson(completionText(payload)) ?? payload);
    if (!parsed.success) {
      throw new Error("Jev returned a response that did not match the expected schema.");
    }

    return { decision: normalise(parsed.data, latencyMs), raw: JSON.stringify(payload) };
  } catch (error) {
    const message = error instanceof Error ? error.message : "unknown Jev failure";
    console.warn(`[jev] live call failed, falling back to DEMO FIXTURE — ${message}`);
    return {
      decision: { ...fallback, latencyMs: Date.now() - startedAt },
      raw: JSON.stringify({ mode: "DEMO_FIXTURE", reason: message }),
      warning: message,
    };
  }
}
