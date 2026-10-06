import { env, hasGeminiKey, hasJevKey } from "./env";
import {
  AuditLog,
  DecisionRecord as DecisionRecordModel,
  GeminiInvestigation as GeminiModel,
  JevDecision as JevModel,
  SecurityEvent,
  Server,
  User,
} from "./models";
import { requireAuth, requireRole, signToken, validate, type AuthUser } from "./middleware";
import { runGemini } from "./services/geminiService";
import { analyzeSecurityEvent, reanalyse, toTriageEvent } from "./services/decisionService";
import { simulationStatus, startSimulation, stopSimulation } from "./simulation";
import {
  SCENARIOS,
  analyzeSecurityEvent as runCore,
  computeMetrics,
  generateEvent,
  scenarioToEvent,
  type Preferences,
  type SecurityEvent as TriageEvent,
  type SimServer,
} from "../../shared";
import bcrypt from "bcryptjs";
import { Router, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";

type Handler = (req: Request, res: Response, next: NextFunction) => Promise<unknown>;

/** Express 4 does not await handlers — wrap them so rejections hit the error handler. */
const wrap =
  (handler: Handler) =>
  (req: Request, res: Response, next: NextFunction): void => {
    void handler(req, res, next).catch(next);
  };

const ROLE_VALUES = ["ADMIN", "SOC_ANALYST", "VIEWER"] as const;
const ROUTE_VALUES = ["CONTAIN", "GRAY", "DISMISS"] as const;
const REVIEW_VALUES = ["PENDING", "APPROVED", "OVERRIDDEN", "DISMISSED"] as const;

/* ----------------------------- validation ---------------------------- */

const PreferencesSchema = z
  .object({
    securitySensitivity: z.number().min(0).max(100),
    riskTolerance: z.number().min(0).max(100),
    availabilityPriority: z.number().min(0).max(100),
    businessContinuity: z.number().min(0).max(100),
    dataProtection: z.number().min(0).max(100),
    automationLevel: z.number().min(0).max(100),
  })
  .partial();

const RegisterSchema = z.object({
  name: z.string().min(2).max(80),
  email: z.string().email(),
  password: z.string().min(6).max(128),
  role: z.enum(ROLE_VALUES).default("SOC_ANALYST"),
});

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const AnalyzeSchema = z.object({
  scenarioKey: z.string().max(64).optional(),
  preferences: PreferencesSchema.optional(),
});

const InlineEventSchema = z.object({
  serverId: z.string().min(3).max(32),
  eventType: z.string().min(2).max(64),
  payload: z.string().min(1).max(2000),
  source: z.string().min(2).max(64),
  user: z.string().max(80).optional(),
  networkContext: z.string().max(300).optional(),
  scope: z.enum(["request", "host", "identity", "data", "anomaly"]).default("anomaly"),
  assetCriticality: z.number().min(1).max(10).default(5),
  dataSensitivity: z.number().min(1).max(10).default(5),
  preferences: PreferencesSchema.optional(),
});

const ReviewSchema = z.object({
  status: z.enum(["APPROVED", "OVERRIDDEN", "DISMISSED"]),
  note: z.string().max(1000).default(""),
  action: z.string().max(32).optional(),
});

const SimulationSchema = z.object({
  speedMs: z.number().min(750).max(30000).default(3000),
});

const EventQuerySchema = z.object({
  threatType: z.string().max(64).optional(),
  severity: z.coerce.number().min(1).max(10).optional(),
  route: z.enum(ROUTE_VALUES).optional(),
  status: z.enum(REVIEW_VALUES).optional(),
  search: z.string().max(120).optional(),
  limit: z.coerce.number().min(1).max(200).default(50),
});

/* -------------------------------- helpers ---------------------------- */

function publicUser(user: { id?: string; _id?: unknown; name: string; email: string; role: string }) {
  return {
    id: String(user.id ?? user._id ?? user.email),
    name: user.name,
    email: user.email,
    role: user.role,
  } as AuthUser;
}

function toSimServer(doc: InstanceType<typeof Server>): SimServer {
  return {
    serverId: doc.serverId,
    hostname: doc.hostname,
    region: doc.region,
    os: doc.os,
    status: doc.status as SimServer["status"],
    threatScore: doc.threatScore,
    criticality: doc.criticality,
    cpu: doc.cpu,
    network: doc.network,
    lastEventAt: doc.lastEventAt ? new Date(doc.lastEventAt).getTime() : null,
  };
}

function leanToSimServer(doc: {
  serverId: string;
  hostname: string;
  region: string;
  os: string;
  status: string;
  threatScore: number;
  criticality: number;
  cpu: number;
  network: number;
  lastEventAt?: Date | null;
}): SimServer {
  return {
    serverId: doc.serverId,
    hostname: doc.hostname,
    region: doc.region,
    os: doc.os,
    status: doc.status as SimServer["status"],
    threatScore: doc.threatScore,
    criticality: doc.criticality,
    cpu: doc.cpu,
    network: doc.network,
    lastEventAt: doc.lastEventAt ? new Date(doc.lastEventAt).getTime() : null,
  };
}

function freshEventId(now = Date.now()): string {
  return `EVT-${now}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`;
}

async function fleetFromDatabase(): Promise<SimServer[] | undefined> {
  const docs = await Server.find().lean();
  return docs.length > 0 ? docs.map(leanToSimServer) : undefined;
}

async function buildEvent(
  scenarioKey?: string,
  explicit?: z.infer<typeof InlineEventSchema>,
): Promise<TriageEvent> {
  const now = Date.now();

  if (explicit) {
    return {
      id: freshEventId(now),
      timestamp: now,
      serverId: explicit.serverId,
      eventType: explicit.eventType,
      payload: explicit.payload,
      source: explicit.source,
      user: explicit.user,
      networkContext: explicit.networkContext,
      scope: explicit.scope,
      assetCriticality: explicit.assetCriticality,
      dataSensitivity: explicit.dataSensitivity,
    };
  }

  if (scenarioKey) {
    const scenario = SCENARIOS.find((entry) => entry.key === scenarioKey);
    if (!scenario) {
      throw Object.assign(new Error(`Unknown scenario: ${scenarioKey}`), { status: 400 });
    }
    return scenarioToEvent(scenario, now, freshEventId(now));
  }

  const fleet = await fleetFromDatabase();
  return generateEvent(fleet ? { fleet, timestamp: now } : { timestamp: now });
}

/* -------------------------------- router ----------------------------- */

export const router = Router();

/* --- health --- */
router.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    ai: {
      jev: hasJevKey() ? "LIVE" : "DEMO_FIXTURE",
      gemini: hasGeminiKey() ? "LIVE" : "DEMO_FIXTURE",
    },
    thresholds: { contain: env.CONTAIN_THRESHOLD, dismiss: env.DISMISS_THRESHOLD },
    simulation: true,
  });
});

/* --- auth --- */
router.post(
  "/auth/register",
  validate(RegisterSchema),
  wrap(async (req, res) => {
    const body = req.body as z.infer<typeof RegisterSchema>;
    const email = body.email.toLowerCase();
    const existing = await User.findOne({ email });
    if (existing) {
      res.status(409).json({ error: "An account with that email already exists." });
      return;
    }
    const passwordHash = await bcrypt.hash(body.password, 12);
    const user = await User.create({
      name: body.name.trim(),
      email,
      passwordHash,
      role: body.role,
    });
    const auth = publicUser(user);
    res.status(201).json({ token: signToken(auth), user: auth });
  }),
);

router.post(
  "/auth/login",
  validate(LoginSchema),
  wrap(async (req, res) => {
    const body = req.body as z.infer<typeof LoginSchema>;
    const user = await User.findOne({ email: body.email.toLowerCase() });
    if (!user) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }
    const ok = await bcrypt.compare(body.password, user.passwordHash);
    if (!ok) {
      res.status(401).json({ error: "Invalid email or password." });
      return;
    }
    const auth = publicUser(user);
    res.json({ token: signToken(auth), user: auth });
  }),
);

router.get(
  "/auth/me",
  requireAuth,
  wrap(async (req, res) => {
    res.json({ user: req.user });
  }),
);

/* --- servers --- */
router.get(
  "/servers",
  requireAuth,
  wrap(async (_req, res) => {
    const docs = await Server.find().sort({ serverId: 1 });
    res.json(docs.map(toSimServer));
  }),
);

router.get(
  "/servers/:id",
  requireAuth,
  wrap(async (req, res) => {
    const doc = await Server.findOne({ serverId: req.params.id });
    if (!doc) {
      res.status(404).json({ error: "Server not found." });
      return;
    }
    const events = await SecurityEvent.find({ serverId: doc.serverId })
      .sort({ timestamp: -1 })
      .limit(20);
    res.json({ server: toSimServer(doc), recentEvents: events });
  }),
);

/* --- events --- */
router.get(
  "/events",
  requireAuth,
  wrap(async (req, res) => {
    const query = EventQuerySchema.parse(req.query);
    const filter: Record<string, unknown> = {};
    if (query.threatType) filter.classification = query.threatType;
    if (query.severity) filter.severity = query.severity;
    if (query.route) filter.routing = query.route;
    if (query.status) filter.status = query.status;
    if (query.search) {
      filter.$or = [
        { eventId: { $regex: query.search, $options: "i" } },
        { serverId: { $regex: query.search, $options: "i" } },
        { payload: { $regex: query.search, $options: "i" } },
      ];
    }
    const docs = await SecurityEvent.find(filter).sort({ timestamp: -1 }).limit(query.limit);
    res.json(docs);
  }),
);

router.get(
  "/events/:id",
  requireAuth,
  wrap(async (req, res) => {
    const doc = await SecurityEvent.findOne({ eventId: req.params.id });
    if (!doc) {
      res.status(404).json({ error: "Event not found." });
      return;
    }
    res.json(await reanalyse(doc));
  }),
);

router.post(
  "/events/analyze",
  requireAuth,
  requireRole("SOC_ANALYST", "ADMIN"),
  validate(AnalyzeSchema),
  wrap(async (req, res) => {
    const body = req.body as z.infer<typeof AnalyzeSchema>;
    const event = await buildEvent(body.scenarioKey);
    const result = await analyzeSecurityEvent({
      scenarioEvent: event,
      preferences: body.preferences as Partial<Preferences> | undefined,
      actor: req.user?.email ?? "analyst",
    });
    res.json(result);
  }),
);

router.post(
  "/events/:id/review",
  requireAuth,
  requireRole("SOC_ANALYST", "ADMIN"),
  validate(ReviewSchema),
  wrap(async (req, res) => {
    const body = req.body as z.infer<typeof ReviewSchema>;
    const doc = await SecurityEvent.findOneAndUpdate(
      { eventId: req.params.id },
      {
        status: body.status,
        reviewNote: body.note,
        reviewedBy: req.user?.email ?? "analyst",
        reviewedAt: new Date(),
      },
      { new: true },
    );
    if (!doc) {
      res.status(404).json({ error: "Event not found." });
      return;
    }
    await AuditLog.create({
      timestamp: new Date(),
      actor: req.user?.email ?? "analyst",
      eventId: doc.eventId,
      action: `REVIEW_${body.status}`,
      metadata: { note: body.note, action: body.action ?? null },
      simulation: true,
    });
    res.json({ ok: true, event: doc });
  }),
);

/* --- decision evaluation (persists a decision record) --- */
router.post(
  "/decisions/evaluate",
  requireAuth,
  validate(InlineEventSchema),
  wrap(async (req, res) => {
    const input = req.body as z.infer<typeof InlineEventSchema>;
    const event = await buildEvent(undefined, input);
    const result = await analyzeSecurityEvent({
      scenarioEvent: event,
      preferences: input.preferences as Partial<Preferences> | undefined,
      actor: req.user?.email ?? "analyst",
    });
    res.json(result);
  }),
);

/* --- what-if (pure re-score, nothing is written) --- */
router.post(
  "/what-if/analyze",
  requireAuth,
  validate(InlineEventSchema),
  wrap(async (req, res) => {
    const input = req.body as z.infer<typeof InlineEventSchema>;
    const event = await buildEvent(undefined, input);
    const preferences: Preferences = {
      riskTolerance: 35,
      securitySensitivity: 70,
      availabilityPriority: 55,
      businessContinuity: 60,
      dataProtection: 75,
      automationLevel: 65,
      ...(input.preferences as Partial<Preferences> | undefined),
    };
    const result = runCore(event, { preferences });
    res.json({
      route: result.route,
      decision: result.decision,
      ranked: result.decision.ranked,
      preferences,
      note: "Re-scored locally from the supplied posture — nothing was persisted.",
    });
  }),
);

/* --- investigations --- */
router.post(
  "/investigations/:eventId/run",
  requireAuth,
  requireRole("SOC_ANALYST", "ADMIN"),
  wrap(async (req, res) => {
    const doc = await SecurityEvent.findOne({ eventId: req.params.eventId });
    if (!doc) {
      res.status(404).json({ error: "Event not found." });
      return;
    }
    const stored = await JevModel.findOne({ eventId: doc.eventId });
    const event = toTriageEvent(doc);

    const jev = stored
      ? {
          maliciousProbability: stored.maliciousProbability,
          classification: stored.classification as never,
          severityScore: stored.severityScore,
          confidence: stored.confidence,
          noul: stored.noul ?? "",
          choice: stored.choice ?? "",
          score: stored.score ?? "",
          evidence: stored.evidence ?? [],
          source: stored.source as "LIVE" | "DEMO_FIXTURE",
          latencyMs: stored.latencyMs,
        }
      : (await analyzeSecurityEvent({ scenarioEvent: event })).jev;

    const result = await runGemini(event, jev);
    await GeminiModel.updateOne(
      { eventId: doc.eventId },
      { $set: { ...result.investigation, rawResponse: result.raw } },
      { upsert: true },
    );
    res.json({ eventId: doc.eventId, investigation: result.investigation });
  }),
);

/* --- simulations --- */
router.post(
  "/simulations/start",
  requireAuth,
  requireRole("SOC_ANALYST", "ADMIN"),
  validate(SimulationSchema),
  wrap(async (req, res) => {
    const body = req.body as z.infer<typeof SimulationSchema>;
    const fleet = (await fleetFromDatabase()) ?? [];
    res.json(await startSimulation(fleet, body.speedMs));
  }),
);

router.post(
  "/simulations/stop",
  requireAuth,
  requireRole("SOC_ANALYST", "ADMIN"),
  wrap(async (_req, res) => {
    res.json(stopSimulation());
  }),
);

router.get(
  "/simulations/status",
  requireAuth,
  wrap(async (_req, res) => {
    res.json(simulationStatus());
  }),
);

/* --- threat overview --- */
router.get(
  "/threats/overview",
  requireAuth,
  wrap(async (_req, res) => {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [grouped, decisions, events] = await Promise.all([
      SecurityEvent.aggregate([
        {
          $group: {
            _id: "$classification",
            count: { $sum: 1 },
            recent: { $sum: { $cond: [{ $gte: ["$timestamp", oneDayAgo] }, 1, 0] } },
            probability: { $avg: "$probability" },
            severity: { $avg: "$severity" },
          },
        },
        { $sort: { count: -1 } },
      ]),
      DecisionRecordModel.find().select("eventId recommendedAction route").limit(1000),
      SecurityEvent.find().select("eventId classification").limit(1000),
    ]);

    const actionByEvent = new Map(decisions.map((doc) => [doc.eventId, doc.recommendedAction]));
    const classByEvent = new Map(events.map((doc) => [doc.eventId, doc.classification]));
    const actionVotes = new Map<string, Map<string, number>>();

    for (const [eventId, action] of actionByEvent) {
      const classification = classByEvent.get(eventId) ?? "Unknown / Other";
      const bucket = actionVotes.get(classification) ?? new Map<string, number>();
      bucket.set(action, (bucket.get(action) ?? 0) + 1);
      actionVotes.set(classification, bucket);
    }

    res.json(
      grouped.map((entry: Record<string, unknown>) => {
        const count = Number(entry.count ?? 0);
        const older = Math.max(count - Number(entry.recent ?? 0), 1);
        const trend = Math.round(((Number(entry.recent ?? 0) - older) / older) * 100);
        const votes = actionVotes.get(String(entry._id ?? "Unknown / Other"));
        const recommended = votes
          ? [...votes.entries()].sort((a, b) => b[1] - a[1])[0][0]
          : "HUMAN REVIEW";
        return {
          threatType: String(entry._id ?? "Unknown / Other"),
          count,
          averageProbability: Number((Number(entry.probability ?? 0)).toFixed(2)),
          averageSeverity: Number((Number(entry.severity ?? 0)).toFixed(1)),
          recommendedAction: recommended,
          trend: Number.isFinite(trend) ? Math.max(-99, Math.min(99, trend)) : 0,
        };
      }),
    );
  }),
);

/* --- reports --- */
router.get(
  "/reports/summary",
  requireAuth,
  wrap(async (req, res) => {
    const [events, decisions, investigations, serverCount, eventCount] = await Promise.all([
      SecurityEvent.find().sort({ timestamp: -1 }).limit(200),
      DecisionRecordModel.countDocuments(),
      GeminiInvestigationCount(),
      Server.countDocuments(),
      SecurityEvent.countDocuments(),
    ]);

    const triageResults = await Promise.all(
      events.map((doc) => reanalyse(doc).catch(() => null)),
    );
    const metrics = computeMetrics(triageResults.filter((entry) => entry !== null) as never[]);

    res.json({
      generatedAt: new Date().toISOString(),
      metrics,
      decisionCount: decisions,
      geminiEscalations: investigations,
      servers: serverCount,
      events: eventCount,
      topThreats: await SecurityEvent.aggregate([
        { $group: { _id: "$classification", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),
      actor: req.user?.email ?? "analyst",
      simulation: true,
    });
  }),
);

async function GeminiInvestigationCount(): Promise<number> {
  return GeminiModel.countDocuments({ source: { $ne: "UNAVAILABLE" } });
}

/* --- audit --- */
router.get(
  "/audit",
  requireAuth,
  wrap(async (req, res) => {
    const limit = Math.min(Number(req.query.limit ?? 200) || 200, 1000);
    const docs = await AuditLog.find().sort({ timestamp: -1 }).limit(limit);
    res.json(
      docs.map((doc) => ({
        id: String(doc._id),
        timestamp: new Date(doc.timestamp).getTime(),
        actor: doc.actor,
        eventId: doc.eventId ?? "—",
        action: doc.action,
        detail: String((doc.metadata as { detail?: string } | undefined)?.detail ?? ""),
      })),
    );
  }),
);
