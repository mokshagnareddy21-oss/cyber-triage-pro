import { Mark, Wordmark } from "@/components/Mark";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/use-auth";
import { motion } from "framer-motion";
import {
  ArrowRight,
  BrainCircuit,
  Check,
  Gauge,
  Layers,
  Network,
  ShieldCheck,
  Timer,
  Wallet,
} from "lucide-react";
import { useNavigate } from "react-router";

const fadeUp = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.5, ease: "easeOut" as const },
};

const FLOW = [
  { step: "01", title: "Fast triage", detail: "Every event scored in one pass" },
  { step: "02", title: "Probability threshold", detail: "0.40 and 0.95 decide the route" },
  { step: "03", title: "Automated decision", detail: "Contain or dismiss, no waiting" },
  { step: "04", title: "Deep forensics", detail: "Only the ambiguous remainder escalates" },
];

const ROUTES = [
  {
    band: "p > 0.95",
    tone: "critical" as const,
    title: "High confidence",
    action: "BLOCK / ISOLATE",
    detail:
      "Containment happens immediately from the fast pass. The deep model is never on the critical path.",
    color: "var(--signal-critical)",
    bg: "var(--signal-critical-bg)",
    line: "var(--signal-critical-line)",
  },
  {
    band: "0.40 ≤ p ≤ 0.95",
    tone: "warning" as const,
    title: "Gray zone",
    action: "THROTTLE → GEMINI",
    detail:
      "The connection is held and a deep forensic pass is bought for exactly the events that need it.",
    color: "var(--signal-warning)",
    bg: "var(--signal-warning-bg)",
    line: "var(--signal-warning-line)",
  },
  {
    band: "p < 0.40",
    tone: "safe" as const,
    title: "Low confidence",
    action: "DISMISS / MONITOR",
    detail:
      "Likely benign. The event is recorded, the analyst is spared, and a deep-model call is saved.",
    color: "var(--signal-safe)",
    bg: "var(--signal-safe-bg)",
    line: "var(--signal-safe-line)",
  },
];

const SCORECARD = [
  { icon: Timer, title: "Speed", detail: "Fast first-pass triage decides high-confidence events in a single pass." },
  { icon: Wallet, title: "Cost", detail: "Fewer deep-model calls — the expensive path is reserved for real doubt." },
  { icon: Gauge, title: "Risk", detail: "Response scales with probability and blast radius, not with a binary alert." },
  { icon: Layers, title: "Explainability", detail: "Every action ships with its why, its risk, and its rejected alternatives." },
  { icon: Network, title: "Adaptability", detail: "Decision factors are explicit weights, so posture changes re-rank the actions." },
  { icon: ShieldCheck, title: "Human oversight", detail: "Ambiguous events stay reviewable — automation never hides a decision." },
];

export default function Landing() {
  const navigate = useNavigate();
  const { isAuthenticated, isLoading } = useAuth();

  const goConsole = () => navigate(isAuthenticated ? "/app" : "/auth?returnTo=%2Fapp");

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* ---------- Nav ---------- */}
      <header className="sticky top-0 z-40 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-5">
          <button
            type="button"
            onClick={() => navigate("/")}
            className="cursor-pointer transition-opacity hover:opacity-70"
          >
            <Wordmark />
          </button>
          <nav className="ml-4 hidden items-center gap-6 text-[13px] text-muted-foreground md:flex">
            <a href="#routing" className="transition-colors hover:text-foreground">
              Routing
            </a>
            <a href="#architecture" className="transition-colors hover:text-foreground">
              Architecture
            </a>
            <a href="#comparison" className="transition-colors hover:text-foreground">
              Why it matters
            </a>
            <a href="#scorecard" className="transition-colors hover:text-foreground">
              Scorecard
            </a>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            {!isLoading && !isAuthenticated && (
              <Button variant="ghost" size="sm" onClick={() => navigate("/auth")}>
                Sign in
              </Button>
            )}
            <Button size="sm" onClick={goConsole} className="gap-1.5">
              {isLoading ? "Launch SOC Console" : isAuthenticated ? "Open console" : "Launch SOC Console"}
              <ArrowRight className="size-4" />
            </Button>
          </div>
        </div>
      </header>

      {/* ---------- Hero ---------- */}
      <section className="relative overflow-hidden border-b">
        <div aria-hidden className="paper-grid pointer-events-none absolute inset-0" />
        <div className="relative mx-auto grid max-w-6xl gap-12 px-5 py-20 lg:grid-cols-[1.15fr_1fr] lg:py-28">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="flex flex-col"
          >
            <span className="text-[11px] font-semibold tracking-[0.24em] text-muted-foreground uppercase">
              Decision Intelligence · Security Operations
            </span>

            <h1 className="mt-6 text-5xl leading-[0.95] font-semibold tracking-[-0.03em] sm:text-6xl">
              CyberSentinel
              <span className="block text-muted-foreground">v2.0</span>
            </h1>

            <p className="mt-5 text-xl font-medium tracking-tight">The Probabilistic SOC Copilot</p>
            <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-muted-foreground">
              Fast probabilistic triage for immediate containment, with deep AI reasoning for
              uncertain threats.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button size="lg" onClick={goConsole} className="gap-2">
                Launch SOC Console
                <ArrowRight className="size-4" />
              </Button>
              <Button size="lg" variant="outline" onClick={() => navigate("/auth?returnTo=%2Fapp")}>
                View architecture
              </Button>
            </div>

            <dl className="mt-12 grid max-w-lg grid-cols-3 gap-px border bg-border">
              {[
                ["1", "fast model pass"],
                ["2", "routing thresholds"],
                ["0", "unexplained actions"],
              ].map(([value, label]) => (
                <div key={label} className="bg-background px-4 py-3">
                  <dt className="text-2xl font-semibold tracking-tight tabular-nums">{value}</dt>
                  <dd className="mt-0.5 text-[11px] leading-tight text-muted-foreground">{label}</dd>
                </div>
              ))}
            </dl>
          </motion.div>

          {/* Routing band */}
          <motion.aside
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.12, ease: "easeOut" }}
            className="flex flex-col justify-center rounded-xl border bg-background p-6"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold tracking-[0.18em] text-muted-foreground uppercase">
                Probability router
              </span>
              <Mark className="size-4 text-muted-foreground" />
            </div>

            <div className="mt-6 flex h-2.5 w-full overflow-hidden rounded-full">
              <div className="h-full" style={{ width: "40%", background: "var(--signal-safe)" }} />
              <div className="h-full" style={{ width: "55%", background: "var(--signal-warning)" }} />
              <div className="h-full" style={{ width: "5%", background: "var(--signal-critical)" }} />
            </div>

            <div className="mt-2 flex justify-between text-[10.5px] text-muted-foreground tabular-nums">
              <span>0.00</span>
              <span className="font-medium text-foreground">0.40</span>
              <span className="font-medium text-foreground">0.95</span>
              <span>1.00</span>
            </div>

            <ul className="mt-6 flex flex-col gap-3">
              {ROUTES.map((route) => (
                <li
                  key={route.title}
                  className="rounded-lg border px-4 py-3"
                  style={{ background: route.bg, borderColor: route.line }}
                >
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="text-[13px] font-semibold" style={{ color: route.color }}>
                      {route.title}
                    </span>
                    <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                      {route.band}
                    </span>
                  </div>
                  <div className="mt-0.5 text-[12.5px] font-medium">{route.action}</div>
                  <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">
                    {route.detail}
                  </p>
                </li>
              ))}
            </ul>
          </motion.aside>
        </div>
      </section>

      {/* ---------- Flow ---------- */}
      <section className="border-b">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <motion.div {...fadeUp} className="flex items-baseline justify-between gap-4">
            <h2 className="text-[11px] font-semibold tracking-[0.2em] text-muted-foreground uppercase">
              The decision path
            </h2>
            <span className="hidden text-[12px] text-muted-foreground sm:block">
              Every event takes exactly this route.
            </span>
          </motion.div>

          <motion.ol {...fadeUp} className="mt-8 grid gap-px border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {FLOW.map((item) => (
              <li key={item.step} className="flex flex-col gap-2 bg-background p-6">
                <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                  {item.step}
                </span>
                <span className="text-[15px] font-semibold tracking-tight">{item.title}</span>
                <span className="text-[12.5px] leading-relaxed text-muted-foreground">
                  {item.detail}
                </span>
              </li>
            ))}
          </motion.ol>
        </div>
      </section>

      {/* ---------- Architecture ---------- */}
      <section id="architecture" className="border-b">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <motion.h2 {...fadeUp} className="text-2xl font-semibold tracking-tight">
            Two systems, deliberately unequal
          </motion.h2>
          <motion.p {...fadeUp} className="mt-3 max-w-2xl text-[14.5px] leading-relaxed text-muted-foreground">
            CyberSentinel asks the cheap question first. Only when the answer is genuinely
            uncertain does it spend money on depth.
          </motion.p>

          <motion.div {...fadeUp} className="mt-10 grid gap-px border bg-border lg:grid-cols-2">
            <div className="flex flex-col gap-4 bg-background p-7">
              <div className="flex items-center gap-3">
                <span className="flex size-9 items-center justify-center rounded-lg border">
                  <Gauge className="size-4" />
                </span>
                <div>
                  <div className="text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                    System 1
                  </div>
                  <div className="text-[15px] font-semibold tracking-tight">Jev · fast triage</div>
                </div>
              </div>
              <p className="text-[13.5px] leading-relaxed text-muted-foreground">
                One structured pass produces three typed answers — probability, classification and
                blast radius — so routing never waits on prose.
              </p>
              <ul className="flex flex-col gap-2 text-[13px]">
                {[
                  "Sub-second probabilistic scoring",
                  "Structured answers: Noul, Choice, Score",
                  "Drives containment and dismissal directly",
                  "Low cost, high throughput",
                ].map((line) => (
                  <li key={line} className="flex gap-2.5 border-b border-border/60 pb-2 last:border-b-0">
                    <Check className="mt-0.5 size-3.5 shrink-0 text-[var(--signal-safe)]" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="flex flex-col gap-4 bg-background p-7">
              <div className="flex items-center gap-3">
                <span className="flex size-9 items-center justify-center rounded-lg border">
                  <BrainCircuit className="size-4" />
                </span>
                <div>
                  <div className="text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                    System 2
                  </div>
                  <div className="text-[15px] font-semibold tracking-tight">
                    Gemini · deep forensics
                  </div>
                </div>
              </div>
              <p className="text-[13.5px] leading-relaxed text-muted-foreground">
                Called only for the gray zone. Returns a structured investigation: root cause,
                ATT&amp;CK mapping, risk factors, containment, remediation and alternatives.
              </p>
              <ul className="flex flex-col gap-2 text-[13px]">
                {[
                  "Invoked only between 0.40 and 0.95",
                  "Structured JSON, section by section",
                  "Generates labelled remediation snippets",
                  "Degrades to human review if unavailable",
                ].map((line) => (
                  <li key={line} className="flex gap-2.5 border-b border-border/60 pb-2 last:border-b-0">
                    <Check className="mt-0.5 size-3.5 shrink-0 text-[var(--signal-ai)]" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          </motion.div>

          <motion.div {...fadeUp} className="mt-6 flex flex-wrap items-center gap-x-3 gap-y-2 text-[13px]">
            <span className="font-medium">React / Vite</span>
            <ArrowRight className="size-3.5 text-muted-foreground" />
            <span className="font-medium">Express REST + JWT</span>
            <ArrowRight className="size-3.5 text-muted-foreground" />
            <span className="font-medium">Decision engine</span>
            <ArrowRight className="size-3.5 text-muted-foreground" />
            <span className="font-medium">MongoDB</span>
            <ArrowRight className="size-3.5 text-muted-foreground" />
            <span className="font-medium">Jev</span>
            <span className="text-muted-foreground">→</span>
            <span className="font-medium">Gemini, when it earns the call</span>
          </motion.div>
        </div>
      </section>

      {/* ---------- Comparison ---------- */}
      <section id="comparison" className="border-b bg-muted/30">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <motion.h2 {...fadeUp} className="text-2xl font-semibold tracking-tight">
            Why CyberSentinel
          </motion.h2>

          <motion.div {...fadeUp} className="mt-8 grid gap-px border bg-border lg:grid-cols-2">
            <div className="bg-background p-7">
              <div className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
                Traditional approach
              </div>
              <p className="mt-3 text-[15px] font-medium">Every event → expensive deep reasoning</p>
              <div className="mt-5 flex flex-col gap-2">
                {["Event", "Deep LLM call", "Deep LLM call", "Deep LLM call", "Answer"].map(
                  (label, index) => (
                    <div
                      key={`${label}-${index}`}
                      className="rounded-md border border-dashed px-3 py-2 text-[12.5px] text-muted-foreground"
                    >
                      {label}
                    </div>
                  ),
                )}
              </div>
              <p className="mt-5 text-[12.5px] leading-relaxed text-muted-foreground">
                Cost and latency scale linearly with volume, and the analyst still has to decide
                what to trust.
              </p>
            </div>

            <div className="bg-background p-7">
              <div className="text-[10px] font-semibold tracking-[0.16em] text-[var(--signal-safe)] uppercase">
                CyberSentinel
              </div>
              <p className="mt-3 text-[15px] font-medium">Triage first, spend depth only on doubt</p>
              <div className="mt-5 flex flex-col gap-2">
                <div className="rounded-md border px-3 py-2 text-[12.5px]">Event</div>
                <div className="rounded-md border px-3 py-2 text-[12.5px]">
                  Fast probabilistic triage
                </div>
                <div className="grid grid-cols-3 gap-2 text-[11.5px]">
                  <div className="rounded-md border px-2 py-2 text-center text-[var(--signal-safe)]">
                    low → dismiss
                  </div>
                  <div className="rounded-md border px-2 py-2 text-center text-[var(--signal-critical)]">
                    high → contain
                  </div>
                  <div className="rounded-md border px-2 py-2 text-center text-[var(--signal-warning)]">
                    gray → deep
                  </div>
                </div>
              </div>
              <p className="mt-5 text-[12.5px] leading-relaxed text-muted-foreground">
                Only the ambiguous remainder reaches the expensive model — and it arrives already
                enriched with probability, classification and telemetry.
              </p>
            </div>
          </motion.div>
        </div>
      </section>

      {/* ---------- Scorecard ---------- */}
      <section id="scorecard" className="border-b">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <motion.h2 {...fadeUp} className="text-2xl font-semibold tracking-tight">
            Decision intelligence scorecard
          </motion.h2>
          <motion.div {...fadeUp} className="mt-8 grid gap-px border bg-border sm:grid-cols-2 lg:grid-cols-3">
            {SCORECARD.map((item) => (
              <div key={item.title} className="flex flex-col gap-2.5 bg-background p-6">
                <item.icon className="size-4 text-muted-foreground" />
                <span className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
                  {item.title}
                </span>
                <span className="text-[13px] leading-relaxed">{item.detail}</span>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ---------- Routing explainer ---------- */}
      <section id="routing" className="border-b">
        <div className="mx-auto max-w-6xl px-5 py-16">
          <motion.h2 {...fadeUp} className="text-2xl font-semibold tracking-tight">
            How the threshold decides
          </motion.h2>
          <motion.div {...fadeUp} className="mt-8 grid gap-px border bg-border lg:grid-cols-3">
            {ROUTES.map((route) => (
              <div key={route.band} className="bg-background p-7">
                <span
                  className="inline-block rounded-full border px-2.5 py-0.5 font-mono text-[11px] tabular-nums"
                  style={{ color: route.color, background: route.bg, borderColor: route.line }}
                >
                  {route.band}
                </span>
                <h3 className="mt-4 text-[15px] font-semibold tracking-tight">{route.action}</h3>
                <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">
                  {route.detail}
                </p>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ---------- CTA ---------- */}
      <section>
        <div className="mx-auto flex max-w-6xl flex-col items-start gap-6 px-5 py-20">
          <motion.h2 {...fadeUp} className="max-w-2xl text-3xl font-semibold tracking-tight">
            Watch a probabilistic decision get made, explained, and reviewed.
          </motion.h2>
          <motion.p {...fadeUp} className="max-w-xl text-[14.5px] leading-relaxed text-muted-foreground">
            The console ships with a seeded fleet, live ingestion, per-event decision timelines and
            analyst review — everything a demo needs on first login.
          </motion.p>
          <motion.div {...fadeUp} className="flex flex-wrap gap-3">
            <Button size="lg" onClick={goConsole} className="gap-2">
              Launch SOC Console
              <ArrowRight className="size-4" />
            </Button>
            <Button size="lg" variant="outline" onClick={() => navigate("/auth")}>
              Create an account
            </Button>
          </motion.div>
        </div>
      </section>

      {/* ---------- Footer ---------- */}
      <footer className="border-t">
        <div className="mx-auto flex max-w-6xl flex-col gap-3 px-5 py-8 text-[12px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <Wordmark />
          <p>
            Demo environment · synthetic infrastructure · containment is simulated and never
            executes against real hosts.
          </p>
        </div>
      </footer>
    </div>
  );
}
