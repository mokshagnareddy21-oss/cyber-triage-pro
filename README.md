# CyberSentinel v2.0 — The Probabilistic SOC Copilot

> **Decision Intelligence** · Fast probabilistic triage for immediate containment, with deep AI
> reasoning for uncertain threats.

CyberSentinel is a security-operations **decision copilot**, not a dashboard and not a chatbot.
It receives synthetic security events, scores them with a fast probabilistic model, and then
**routes** each event on a number:

| Malicious probability | Route | What happens |
| --------------------- | ----- | ------------ |
| `p > 0.95` | **CONTAIN** | Simulated containment runs immediately. The deep model is never on the critical path. |
| `0.40 ≤ p ≤ 0.95` | **GRAY** | The event is throttled and escalated to Gemini for structured forensics. |
| `p < 0.40` | **DISMISS** | Recorded as likely benign. No deep-model call is spent. |

Every event leaves the system with a **decision**, a **reason**, a **risk**, a set of
**alternatives**, a **confidence** figure and a **decision timeline**. Nothing is asserted
without evidence, and nothing is ever labelled as a live model result unless a live model
produced it.

---

## 1. Problem statement

Security operations centres are drowning in events. The naive fix — send everything to a large
model for deep reasoning — is slow, expensive, and still leaves the analyst to guess *why* a
recommendation was made. The opposite extreme, signature-only alerting, produces alerts with no
reasoning attached at all.

The real problem is not detection. It is **deciding, quickly and defensibly, how much reasoning
each event deserves.**

## 2. Solution

CyberSentinel splits the work across two deliberately unequal systems:

- **System 1 — Jev**: one fast structured pass that answers three typed questions
  (*Noul* = probability, *Choice* = classification, *Score* = blast radius).
- **System 2 — Gemini**: deep forensic reasoning, invoked **only** for the events the fast pass
  could not resolve.

A pair of thresholds turns the probability into a routing decision, and a scoring engine turns
the routing decision into a ranked, explained set of actions. The result is an interface where a
judge can watch a machine reason under uncertainty — including watching it decide *not* to act.

**Why this qualifies as Decision Intelligence:** the product's primary output is not
"classification" but *action under uncertainty*. It quantifies confidence, compares alternative
actions against configurable weights, exposes the trade-off between containment and disruption,
reports the cost of each path, and keeps a human in the loop exactly where the model is unsure.

---

## 3. Version 1 scope

Version 1 is intentionally narrow. It does **one** loop end to end:

1. **Ingest events + auto-triage** — a live streaming queue backed by the routing engine.
2. **Main screen: live event triage queue** — `/app`.
3. **Single event deep-dive** — the incident drawer with payload, telemetry, evidence, MITRE,
   forensics and audit history.
4. **Decision timeline with confidence** — every step the system took, with its confidence figure
   and its latency.
5. **Analyst review + approve actions** — approve, override with an alternative action, or mark a
   false positive, with role-based permissions.

Deliberately **out of** version 1 (roadmap): What-If Lab, the 50-server global matrix page,
threat-intelligence charts, report exports, the AI chat assistant, and SSE streaming. They are
listed in *Future improvements* rather than shipped as placeholders — there are no dead routes
and no stub buttons in this repository.

---

## 4. Architecture

```
React / Vite / Tailwind  ──REST (JWT)──▶  Node.js + Express
                                              │
                                     Decision / Security Engine
                                       (shared/ — one implementation)
                                              │
                                           MongoDB
                                              │
                                     Jev API  (System 1)
                                              │
                            Gemini API  (System 2, gray zone only)
```

The frontend **never** calls Jev or Gemini directly, and no model key is ever present in a
browser bundle.

```
/
├── src/                  Vite React frontend
│   ├── core/             thin barrel re-exporting ../shared
│   ├── components/       AppShell, IncidentDrawer, DecisionTimeline, chips, …
│   ├── lib/              api.ts (REST transport), auth.tsx (JWT), store.tsx (queue)
│   └── pages/            Landing, Auth, Console, NotFound
├── shared/               shared decision core (used by BOTH sides)
│   ├── types.ts          domain model
│   ├── thresholds.ts     0.40 / 0.95 routing thresholds, action costs, MITRE map
│   ├── decision.ts       scoring, explanations, risk factors, timeline builder
│   ├── fixtures.ts       8 named scenarios + deterministic Jev/Gemini fixtures
│   ├── telemetry.ts      50-server fleet, synthetic event pool, telemetry
│   └── triage.ts         analyzeSecurityEvent — the routing pipeline
├── backend/              Express API
│   ├── src/models.ts     7 Mongoose models
│   ├── src/services/     jevService, geminiService, containmentService, decisionService
│   ├── src/routes.ts     REST endpoints (Zod-validated)
│   └── src/seed.ts       50 servers + demo users + history
├── .env.example          (see §8 — the sandbox blocks creating this filename; use backend/env.example)
└── README.md
```

**Why a `shared/` directory?** Routing, scoring and fixtures exist in exactly one place. The
queue UI, the drawer, the REST responses and the Express process all import the same functions,
so the browser and the API cannot disagree about a decision.

---

## 5. Tech stack

| Layer | Choice |
| ----- | ------ |
| Frontend | React 19, Vite 7, React Router 7, Tailwind CSS v4, shadcn/ui, Recharts, Lucide, Framer Motion |
| Backend | Node.js, Express 4, JWT (`jsonwebtoken`), bcrypt (`bcryptjs`), Zod, helmet, CORS, express-rate-limit, dotenv |
| Database | MongoDB + Mongoose (MongoDB Atlas) |
| Fast model | TypeSafe Jev / System One (`JEV_API_KEY`, `JEV_API_URL`, `JEV_MODEL`) |
| Deep model | Google Gemini (`GEMINI_API_KEY`, `GEMINI_MODEL`) |
| Language | TypeScript throughout |

`bcryptjs` is used instead of native `bcrypt` because it is a drop-in API-compatible pure-JS
implementation — identical hashing semantics, no native build step on deploy.

---

## 6. AI architecture

### 6.1 Why Jev for fast structured decisions

Jev is asked three **typed** questions instead of being asked to write prose:

- **Noul** — *"Does this event represent a malicious attempt to execute unauthorized commands,
  bypass security controls, access credentials, or exfiltrate sensitive information?"* → a
  probability.
- **Choice** — classify into exactly one of ten classes (SQL Injection, Prompt Injection,
  Ransomware Signature, Credential Attack, Insider Threat, Data Exfiltration, Malware,
  Privilege Escalation, Benign Anomaly, Unknown / Other).
- **Score** — rate immediate blast radius from 1 to 10.

Typed answers can be parsed, validated and *routed*. A paragraph cannot. Because the response is
bounded, one pass is enough to decide whether anything further is needed — which is what makes
sub-second triage possible.

### 6.2 Why Gemini only for uncertain cases

Deep reasoning is expensive and slow. Spending it on an event with `p = 0.99` buys nothing: the
decision is already obvious. Spending it on `p = 0.12` is worse — it burns budget to confirm
benignness. The only events where depth changes the outcome are the ones in the middle, so those
are the only ones that escalate.

Gemini receives the original event, the Jev probability, classification, severity, relevant
telemetry, server context and the simulated threat context, and must return **structured JSON**
matching a fixed schema: threat summary, attack classification, root cause, evidence, MITRE
ATT&CK mapping, impact assessment, risk factors, recommended containment, recommended
remediation, confidence explanation, alternative actions, and an optional remediation script.

Remediation snippets are always rendered under a **SIMULATION / HUMAN REVIEW REQUIRED** banner
and are never executed.

### 6.3 How the threshold determines routing

```
p > 0.95          → CONTAIN   act now, containment is simulated, Gemini skipped (cost avoided)
0.40 ≤ p ≤ 0.95   → GRAY      throttle, then buy a deep pass
p < 0.40          → DISMISS   record and move on (cost avoided)
```

The thresholds are constants in `shared/thresholds.ts` and can be overridden with
`CONTAIN_THRESHOLD` / `DISMISS_THRESHOLD`. Because routing and scoring are separate, a gray-zone
event can still receive an `ISOLATE` recommendation after forensics — routing says *how much
thinking to spend*, scoring says *what to do*.

### 6.4 LIVE vs DEMO FIXTURE — never blurred

- `JEV_API_KEY` / `GEMINI_API_KEY` **set** → the backend performs real HTTP calls, times them,
  validates the response with Zod, and returns `source: "LIVE"`.
- Keys **unset** → deterministic fixtures with `source: "DEMO_FIXTURE"`.
- Key set but the **call fails** → Gemini returns `source: "UNAVAILABLE"`, the UI shows
  **GEMINI UNAVAILABLE**, and the event safely falls back to **HUMAN REVIEW REQUIRED**.

The top bar always shows `AI MODE · LIVE` or `AI MODE · DEMO FIXTURE`. The console additionally
shows `API CONNECTED` or `LOCAL ENGINE` depending on whether the Express API answered its health
probe. **Mock output is never presented as real AI output.**

The Freebuff preview has no reachable backend, so it runs in `LOCAL ENGINE + DEMO FIXTURE` mode
by design and says so on screen. The decision logic is the *same* code — only the transport
differs.

---

## 7. Database schema

| Model | Fields |
| ----- | ------ |
| **User** | `name`, `email` (unique), `passwordHash`, `role` (`ADMIN` \| `SOC_ANALYST` \| `VIEWER`), `createdAt` |
| **Server** | `serverId` (unique), `hostname`, `region`, `os`, `status`, `threatScore`, `criticality`, `cpu`, `network`, `lastEventAt` |
| **SecurityEvent** | `eventId` (unique), `timestamp`, `serverId`, `eventType`, `payload`, `source`, `user`, `networkContext`, `scope`, `assetCriticality`, `dataSensitivity`, `probability`, `classification`, `severity`, `routing`, `status`, `reviewedBy`, `reviewNote`, `jevLatencyMs`, `geminiLatencyMs`, `totalDecisionLatencyMs`, `simulated`, `createdAt` |
| **JevDecision** | `eventId`, `maliciousProbability`, `classification`, `severityScore`, `confidence`, `noul`, `choice`, `score`, `evidence`, `rawResponse`, `source`, `latencyMs`, `createdAt` |
| **GeminiInvestigation** | `eventId`, `summary`, `classification`, `rootCause`, `evidence`, `mitre[]`, `impact`, `risks[]`, `recommendedAction`, `containment`, `remediation`, `confidenceExplanation`, `alternatives[]`, `remediationCode`, `remediationLanguage`, `source`, `rawResponse`, `latencyMs`, `createdAt` |
| **DecisionRecord** | `eventId`, `route`, `recommendedAction`, `alternativeActions[]`, `decisionFactors`, `riskTolerance`, `securitySensitivity`, `availabilityPriority`, `confidence`, `explanation`, `createdAt` |
| **AuditLog** | `timestamp`, `actor`, `eventId`, `action`, `metadata`, `simulation`, `createdAt` |

Only `Server.status` and the review fields on `SecurityEvent` are ever updated in place. The
audit and decision trails are append-only and cannot be edited from the interface.

---

## 8. Environment variables

### Backend — `backend/env.example`

> The Freebuff sandbox blocks writing a file literally named `.env.example`. Copy the template:
> `cp backend/env.example backend/.env`, then fill it in.

```env
PORT=4000
CLIENT_URL=http://localhost:5173
MONGODB_URI=mongodb+srv://USER:PASSWORD@cluster0.mongodb.net/cybersentinel
JWT_SECRET=replace-with-a-long-random-string
JWT_EXPIRES_IN=12h
JEV_API_KEY=
JEV_API_URL=https://api.typesafe.ai/v1/complete
JEV_MODEL=typesafe-jev-1
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-pro
CONTAIN_THRESHOLD=0.95
DISMISS_THRESHOLD=0.40
```

### Frontend

```env
# Full URL of the deployed Express API. Unset → the console runs the local engine.
# A trailing /api is tolerated and stripped automatically.
VITE_API_URL=http://localhost:4000
```

**Never** put `JEV_API_KEY`, `GEMINI_API_KEY`, `MONGODB_URI` or `JWT_SECRET` in a `VITE_`-prefixed
variable — anything prefixed `VITE_` is inlined into the public bundle. No API key is ever
written to a log line.

---

## 9. API endpoints

| Method | Path | Auth | Notes |
| ------ | ---- | ---- | ----- |
| `GET` | `/api/health` | public | readiness + which model mode is active |
| `POST` | `/api/auth/register` | public | Zod-validated, bcrypt-hashed (cost 12) |
| `POST` | `/api/auth/login` | public | rate-limited 40 / 15 min |
| `GET` | `/api/auth/me` | JWT | current session |
| `GET` | `/api/servers` | JWT | 50 synthetic hosts |
| `GET` | `/api/servers/:id` | JWT | host + last 20 events |
| `GET` | `/api/events` | JWT | filters: `threatType`, `severity`, `route`, `status`, `search`, `limit` |
| `GET` | `/api/events/:id` | JWT | full `TriageResult` |
| `POST` | `/api/events/analyze` | JWT · analyst | **the routing engine** — 11 steps |
| `POST` | `/api/events/:id/review` | JWT · analyst | approve / override / dismiss |
| `POST` | `/api/decisions/evaluate` | JWT | score an inline event, persists a decision |
| `POST` | `/api/what-if/analyze` | JWT | re-score under different posture, writes nothing |
| `POST` | `/api/investigations/:eventId/run` | JWT · analyst | force a Gemini escalation |
| `POST` | `/api/simulations/start` | JWT · analyst | start the synthetic attack wave |
| `POST` | `/api/simulations/stop` | JWT · analyst | stop it |
| `GET` | `/api/simulations/status` | JWT | counters |
| `GET` | `/api/threats/overview` | JWT | per-class counts, averages, action, trend |
| `GET` | `/api/reports/summary` | JWT | metrics + top threats |
| `GET` | `/api/audit` | JWT | append-only trail |

All responses are JSON. Errors return `{ "error": "human readable message" }`; validation failures
add an `details[]` array. A single centralised Express error handler is the only place that
formats failures.

---

## 10. Local setup

```bash
# 1. frontend
bun install
bun run dev            # http://localhost:5173

# 2. backend
cd backend
bun install
cp env.example .env    # then edit MONGODB_URI, JWT_SECRET, and optionally the model keys

# 3. database — create a free MongoDB Atlas cluster, allow your IP, paste the URI

# 4. seed 50 servers, demo users and history
bun run seed

# 5. run the API
bun run dev            # http://localhost:4000

# 6. point the frontend at it
#    create .env.local in the project root with:
#    VITE_API_URL=http://localhost:4000
```

### Development commands

| Where | Command | Purpose |
| ----- | ------- | ------- |
| root | `bun run dev` | Vite dev server |
| root | `bun tsc -b --noEmit` | typecheck |
| root | `bun run build` | production build (`tsc -b && vite build`) |
| root | `bun run lint` / `bun run format` | ESLint / Prettier |
| `backend/` | `bun run dev` | API with reload |
| `backend/` | `bun run seed` | seed the database |
| `backend/` | `bun run typecheck` | typecheck API + shared core |
| `backend/` | `bun run start` | production start |

---

## 11. Deployment

**Frontend → Vercel or Netlify**

- Build command `bun run build`, output directory `dist`.
- Set `VITE_API_URL` to the deployed API origin (for example `https://cybersentinel-api.onrender.com`).
- No model keys are needed — and none must be added.

**Backend → Render or Railway**

- Root directory `backend`, start command `bun run start` (or `npx tsx src/index.ts`).
- Set `PORT` (usually supplied by the platform), `MONGODB_URI`, `JWT_SECRET`,
  `CLIENT_URL` (the deployed frontend origin), and `JEV_API_KEY` / `GEMINI_API_KEY` for live mode.
- Set `CONTAIN_THRESHOLD` / `DISMISS_THRESHOLD` only if you want to move the routing bands.

**Database → MongoDB Atlas**

- Free M0 cluster is plenty for the demo.
- Add the platform's egress IPs to the allow-list and use a read/write user for one database.

---

## 12. Demo instructions

1. Open the app → **Launch SOC Console**.
2. Sign in with a demo credential (below).
3. The queue is already populated with 26 historical events.
4. Press **Resume stream** and watch events arrive, triage, and route in real time.
5. Pick a scenario from **Run a scenario…** to fire a deterministic event:
   - *Benign Traffic* → `DISMISS` / ALLOW
   - *Suspicious API Activity* → `GRAY` / THROTTLE + Gemini
   - *SQL Injection* → `CONTAIN` / BLOCK
   - *Prompt Injection* → `CONTAIN` / BLOCK
   - *Ransomware Indicators* → `CONTAIN` / ISOLATE
   - *Credential Exfiltration* → `CONTAIN` / BLOCK
   - *Insider Threat* → `GRAY` / escalation
   - *Unknown Zero-Day-like Event* → `GRAY` / THROTTLE + Gemini
6. Click any row → the incident drawer opens on **Decision**, then step through **Timeline**,
   **Telemetry**, **Forensics** and **Review**.
7. Approve, override, or dismiss the decision — your choice is written to the audit trail.

### Demo credentials

> **Demo use only.** Never reuse these anywhere real.

| Email | Password | Role |
| ----- | -------- | ---- |
| `admin@cybersentinel.dev` | `sentinel` | `ADMIN` |
| `analyst@cybersentinel.dev` | `sentinel` | `SOC_ANALYST` |
| `viewer@cybersentinel.dev` | `sentinel` | `VIEWER` |

Permissions: **ADMIN** can do everything; **SOC_ANALYST** investigates, runs scenarios and records
reviews; **VIEWER** has read-only access to the queue, timelines and audit trail.

---

## 13. Design notes — Minimalism

The interface is a near-monochrome, hairline-ruled operational surface: paper and ink, generous
whitespace, tabular numerals, and colour used **only** to carry state.

| Colour | Meaning |
| ------ | ------- |
| Red | hostile / contained |
| Amber | unresolved / under investigation |
| Green | safe / dismissed |
| Blue | neutral telemetry |
| Violet | model reasoning (Gemini, DEMO FIXTURE) |

No neon, no gradient hero, no stock cyberpunk. It is an instrument, not a poster.

---

## 14. Screenshots

Add captures to `docs/screenshots/`:

| File | Screen |
| ---- | ------ |
| `01-landing.png` | Landing page — hero, probability router, architecture |
| `02-auth.png` | Sign in with demo credentials |
| `03-queue.png` | Live event triage queue with the metric strip |
| `04-decision.png` | Incident drawer — Decision tab |
| `05-timeline.png` | Decision timeline with per-step confidence |
| `06-forensics.png` | Gemini deep investigation (gray-zone event) |
| `07-review.png` | Decision matrix + analyst approval |

---

## 15. Verification performed

- `bun tsc -b --noEmit` — passes (this is the gate the platform runs).
- `bun run build` — production build succeeds; routes are code-split.
- `cd backend && bun run typecheck` — API + shared core pass.
- `cd backend && bun install` — installs cleanly (129 packages).
- `bun run lint` — all CyberSentinel source files are clean. Three pre-existing errors remain in
  untouched shadcn/ui template files (`ui/carousel.tsx`, `ui/sidebar.tsx`, `hooks/use-mobile.ts`)
  that the app does not render; they were failing before this project and are left alone rather
  than patched with suppressions.

Not verified in this environment (no Atlas instance, no model keys, and the preview sandbox does
not permit running a long-lived Node process): a live Mongo connection, a live Jev call, and a
live Gemini call. Each path is implemented, validated and falls back explicitly — and the UI
labels which mode it is in.

---

## 16. Future improvements

- What-If Lab with posture sliders (the scoring engine already accepts a full preferences object).
- Global Threat Matrix for all 50 servers with live status transitions.
- Threat Intelligence charts and CSV/JSON report exports.
- Server-Sent Events instead of interval-based ingestion.
- AI Security Assistant wired to `POST /api/events/analyze`.
- Case management: assign incidents to analysts, link related events.
