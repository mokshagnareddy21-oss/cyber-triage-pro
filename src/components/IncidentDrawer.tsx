import {
  Chip,
  ConfidenceBar,
  LatencyBadge,
  TEXT_TONE,
  routeLabel,
  toneForReview,
  toneForRoute,
  type Tone,
} from "@/components/chips";
import { DecisionMatrix } from "@/components/DecisionMatrix";
import { DecisionTimeline } from "@/components/DecisionTimeline";
import {
  ACTION_PROFILE,
  eventTelemetry,
  savingsNote,
} from "@/core";
import { useAuth } from "@/hooks/use-auth";
import type { ReviewDraft } from "@/lib/store";
import { useTriage } from "@/lib/store";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { motion } from "framer-motion";
import {
  Activity,
  BrainCircuit,
  ClipboardCheck,
  Copy,
  Eye,
  FileSearch,
  Gavel,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

const TABS = [
  { value: "decision", label: "Decision", icon: Gavel },
  { value: "timeline", label: "Timeline", icon: Activity },
  { value: "telemetry", label: "Telemetry", icon: ShieldAlert },
  { value: "forensics", label: "Forensics", icon: BrainCircuit },
  { value: "review", label: "Review", icon: ClipboardCheck },
] as const;

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 border-b border-border/60 py-2.5 last:border-b-0">
      <dt className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">{label}</dt>
      <dd className="text-[13px] leading-snug font-medium break-words">{value}</dd>
    </div>
  );
}

function Section({
  title,
  tone,
  children,
}: {
  title: string;
  tone?: "critical" | "warning" | "safe" | "ai" | "neutral";
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2">
      <h3
        className={cn(
          "text-[10px] font-semibold tracking-[0.16em] uppercase",
          tone === "critical" && "text-[var(--signal-critical)]",
          tone === "warning" && "text-[var(--signal-warning)]",
          tone === "safe" && "text-[var(--signal-safe)]",
          tone === "ai" && "text-[var(--signal-ai)]",
          (!tone || tone === "neutral") && "text-muted-foreground",
        )}
      >
        {title}
      </h3>
      <div className="text-[13px] leading-relaxed text-foreground/90">{children}</div>
    </section>
  );
}

export function IncidentDrawer() {
  const { results, selectedId, select, review, audit, fleet } = useTriage();
  const { user } = useAuth();
  const [override, setOverride] = useState<string>("");
  const [note, setNote] = useState("");
  const [copied, setCopied] = useState(false);

  const result = results.find((entry) => entry.event.id === selectedId) ?? null;
  const server = fleet.find((entry) => entry.serverId === result?.event.serverId) ?? null;
  const canReview = user?.role === "ADMIN" || user?.role === "SOC_ANALYST";
  const entries = audit.filter((entry) => entry.eventId === selectedId);

  const close = () => select(null);

  const submit = async (status: ReviewDraft["status"]) => {
    if (!result) return;
    await review(result.event.id, {
      status,
      note: note.trim(),
      action: status === "OVERRIDDEN" ? override : undefined,
    });
    setNote("");
    setOverride("");
  };

  const copyCode = async () => {
    if (!result?.gemini?.remediationCode) return;
    try {
      await navigator.clipboard.writeText(result.gemini.remediationCode);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      toast.error("Clipboard unavailable", { description: "Select the snippet manually." });
    }
  };

  return (
    <Sheet open={selectedId !== null} onOpenChange={(open) => !open && close()}>
      <SheetContent
        side="right"
        className="gap-0 overflow-y-auto border-l bg-background p-0 sm:max-w-2xl md:max-w-3xl [&>button]:z-50"
      >
        {!result ? (
          <div className="flex h-full items-center justify-center p-8 text-sm text-muted-foreground">
            Select an event to inspect it.
          </div>
        ) : (
          <>              <SheetHeader className="sticky top-0 z-10 gap-0 border-b bg-background/95 p-5 pr-14 backdrop-blur">
              <div className="flex flex-wrap items-center gap-2">
                <Chip tone={toneForRoute(result.route)} pulse>
                  {routeLabel(result.route)}
                </Chip>
                <Chip tone={toneForReview(result.reviewStatus)}>
                  {result.reviewStatus}
                </Chip>
                <Chip tone={result.jev.source === "LIVE" ? "safe" : "ai"}>
                  {result.jev.source === "LIVE" ? "LIVE MODEL" : "DEMO FIXTURE"}
                </Chip>
                <Chip tone="neutral">DEMO SIMULATION</Chip>
              </div>
              <SheetTitle className="mt-3 text-xl font-bold tracking-tight">
                {result.event.eventType.split("_").join(" ")}
              </SheetTitle>
              <SheetDescription className="mt-1 font-mono text-xs">
                {result.event.id} · {result.event.serverId}
                {server ? ` · ${server.hostname}` : ""} ·{" "}
                {new Date(result.event.timestamp).toLocaleString()}
              </SheetDescription>
            </SheetHeader>

            <Tabs defaultValue="decision" className="flex flex-col gap-0">
              <TabsList className="mx-5 w-fit max-w-full justify-start gap-1 overflow-x-auto rounded-none border-b bg-background p-0">
                {TABS.map((tab) => (
                  <TabsTrigger
                    key={tab.value}
                    value={tab.value}
                    className="rounded-none border-b-2 border-transparent px-3 text-[12px] data-[state=active]:border-foreground data-[state=active]:bg-transparent data-[state=active]:shadow-none"
                  >
                    <tab.icon className="size-3.5" />
                    {tab.label}
                  </TabsTrigger>
                ))}
              </TabsList>

              {/* ---------------- DECISION ---------------- */}
              <TabsContent value="decision" className="flex flex-col gap-7 px-5 py-6">
                <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4">
                  <Metric label="Threat probability" value={`${Math.round(result.jev.maliciousProbability * 100)}%`} tone={toneForRoute(result.route)} />
                  <Metric label="Severity" value={`${result.jev.severityScore} / 10`} />
                  <Metric label="Confidence" value={`${Math.round(result.jev.confidence * 100)}%`} />
                  <Metric
                    label="Sensitive data"
                    value={result.event.dataSensitivity >= 8 ? "DETECTED" : "NOT FLAGGED"}
                    tone={result.event.dataSensitivity >= 8 ? "critical" : "neutral"}
                  />
                </div>

                <div className="flex flex-wrap items-center gap-3 border-y border-border py-4">
                  <span className="text-[10px] tracking-[0.16em] text-muted-foreground uppercase">
                    Recommendation
                  </span>
                  <span className="text-lg font-semibold tracking-tight">
                    {result.decision.action}
                  </span>
                  <Chip tone={toneForRoute(result.route)}>
                    {ACTION_PROFILE[result.decision.action].short}
                  </Chip>
                  <span className="ml-auto flex items-center gap-2 text-[11px] text-muted-foreground tabular-nums">
                    decision confidence
                    <span className="w-24">
                      <ConfidenceBar
                        value={result.decision.confidence}
                        tone={toneForRoute(result.route)}
                      />
                    </span>
                    {Math.round(result.decision.confidence * 100)}%
                  </span>
                </div>

                <Section title="Why this action?" tone="neutral">
                  <p>{result.decision.why}</p>
                </Section>

                <Section title="Risk if this action is not taken" tone="critical">
                  <p>{result.decision.riskIfNotTaken}</p>
                </Section>

                <div className="grid gap-7 sm:grid-cols-2">
                  <Section title="Decision factors" tone="neutral">
                    <dl className="flex flex-col">
                      <Field label="Threat probability" value={`${result.decision.factors.threatProbability}%`} />
                      <Field label="Severity" value={`${result.decision.factors.severity} / 10`} />
                      <Field label="Asset criticality" value={`${result.decision.factors.assetCriticality} / 10`} />
                      <Field label="Data sensitivity" value={`${result.decision.factors.dataSensitivity} / 10`} />
                      <Field label="Business impact" value={`${result.decision.factors.businessImpact}%`} />
                      <Field label="Risk tolerance" value={`${result.decision.factors.riskTolerance} / 100`} />
                      <Field label="Availability priority" value={`${result.decision.factors.availabilityPriority} / 100`} />
                      <Field label="Automation preference" value={`${result.decision.factors.automationLevel} / 100`} />
                    </dl>
                  </Section>

                  <Section title="Evidence" tone="neutral">
                    <ul className="flex flex-col gap-2">
                      {result.decision.evidence.map((line) => (
                        <li
                          key={line}
                          className="flex gap-2 border-b border-border/60 pb-2 text-[12.5px] last:border-b-0"
                        >
                          <span className="mt-1.5 size-1 shrink-0 rounded-full bg-foreground/60" />
                          <span className="text-muted-foreground">{line}</span>
                        </li>
                      ))}
                    </ul>
                  </Section>
                </div>

                <Section title="Alternatives considered" tone="neutral">
                  <ul className="flex flex-col divide-y divide-border/60">
                    {result.decision.alternatives.map((option) => (
                      <li key={option.action} className="flex flex-col gap-1 py-3">
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-[13px] font-semibold">{option.action}</span>
                          <span className="text-[11px] text-muted-foreground tabular-nums">
                            fit {Math.round(option.score * 100)}
                          </span>
                        </div>
                        <p className="text-[12.5px] text-muted-foreground">{option.why}</p>
                        <p className="text-[11.5px] text-muted-foreground/80">
                          Trade-off — {option.tradeoff}
                        </p>
                      </li>
                    ))}
                  </ul>
                </Section>
              </TabsContent>

              {/* ---------------- TIMELINE ---------------- */}
              <TabsContent value="timeline" className="flex flex-col gap-6 px-5 py-6">
                <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-border pb-4">
                  <LatencyBadge ms={result.latency.jevMs} label="Jev" />
                  <LatencyBadge ms={result.latency.geminiMs} label="Gemini" />
                  <LatencyBadge ms={result.latency.totalMs} label="Total" />
                  <Chip tone="neutral">DEMO SIMULATION</Chip>
                </div>

                <DecisionTimeline steps={result.timeline} animateKey={result.event.id} />

                {savingsNote(result.route) && (
                  <div className="rounded-lg border border-[var(--signal-safe-line)] bg-[var(--signal-safe-bg)] px-4 py-3">
                    <p className="text-[10px] font-semibold tracking-[0.14em] text-[var(--signal-safe)] uppercase">
                      Cost-aware routing
                    </p>
                    <p className="mt-1 text-[13px] text-foreground/90">
                      {savingsNote(result.route)}
                    </p>
                  </div>
                )}
              </TabsContent>

              {/* ---------------- TELEMETRY ---------------- */}
              <TabsContent value="telemetry" className="flex flex-col gap-6 px-5 py-6">
                <div className="grid gap-6 sm:grid-cols-2">
                  <Section title="Event payload" tone="neutral">
                    <dl className="flex flex-col">
                      <Field label="Source" value={result.event.source} />
                      <Field label="Reporter" value={result.event.user ?? "—"} />
                      <Field label="Event ID" value={<span className="font-mono">{result.event.id}</span>} />
                      <Field label="Server" value={`${result.event.serverId}${server ? ` · ${server.hostname}` : ""}`} />
                      <Field
                        label="Asset criticality"
                        value={`${result.event.assetCriticality} / 10`}
                      />
                      <Field
                        label="Data sensitivity"
                        value={`${result.event.dataSensitivity} / 10`}
                      />
                      <Field label="Network context" value={result.event.networkContext ?? "—"} />
                    </dl>
                  </Section>

                  <Section title="Observed signal" tone="neutral">
                    <p className="mb-3 border-l-2 border-border pl-3 font-mono text-[12px] leading-relaxed break-all text-muted-foreground">
                      {result.event.payload}
                    </p>
                    <ul className="flex flex-col gap-1.5">
                      {result.jev.evidence.map((line) => (
                        <li key={line} className="text-[12.5px] text-muted-foreground">
                          {line}
                        </li>
                      ))}
                    </ul>
                  </Section>
                </div>

                <Section title="Telemetry window" tone="neutral">
                  <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-3">
                    {Object.entries(eventTelemetry(result.event)).map(([key, value]) => (
                      <div key={key} className="flex flex-col gap-1 bg-background px-3 py-2.5">
                        <span className="text-[10px] tracking-[0.1em] text-muted-foreground uppercase">
                          {key.replace(/([A-Z])/g, " $1")}
                        </span>
                        <span className="text-[13px] font-semibold tabular-nums">
                          {Array.isArray(value)
                            ? value.length > 0
                              ? value.join(", ")
                              : "none"
                            : String(value)}
                        </span>
                      </div>
                    ))}
                  </div>
                </Section>
              </TabsContent>

              {/* ---------------- FORENSICS ---------------- */}
              <TabsContent value="forensics" className="flex flex-col gap-6 px-5 py-6">
                {result.route !== "GRAY" ? (
                  <div className="rounded-lg border bg-muted/50 px-4 py-6 text-center">
                    <Eye className="mx-auto size-5 text-muted-foreground" />
                    <p className="mt-3 text-[13px] font-semibold">
                      Deep analysis was not required
                    </p>
                    <p className="mx-auto mt-1 max-w-md text-[12.5px] text-muted-foreground">
                      {savingsNote(result.route)} The fast model's confidence was sufficient to
                      decide on its own.
                    </p>
                  </div>
                ) : result.gemini?.source === "UNAVAILABLE" ? (
                  <div className="rounded-lg border border-[var(--signal-critical-line)] bg-[var(--signal-critical-bg)] px-4 py-5">
                    <p className="text-[10px] font-semibold tracking-[0.16em] text-[var(--signal-critical)] uppercase">
                      Gemini unavailable
                    </p>
                    <p className="mt-2 text-[13px] leading-relaxed">
                      {result.gemini.error} The system will not guess: this event falls back to{" "}
                      <strong>HUMAN REVIEW REQUIRED</strong> and stays on the queue until an
                      analyst decides.
                    </p>
                  </div>
                ) : result.gemini ? (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35 }}
                    className="flex flex-col gap-6"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Chip tone="ai" pulse>
                        GEMINI DEEP INVESTIGATION
                      </Chip>
                      <Chip tone={result.gemini.source === "LIVE" ? "safe" : "ai"}>
                        {result.gemini.source === "LIVE" ? "LIVE MODEL" : "DEMO FIXTURE"}
                      </Chip>
                      <LatencyBadge ms={result.gemini.latencyMs} label="Gemini" />
                    </div>

                    <Section title="Threat summary" tone="ai">
                      {result.gemini.summary}
                    </Section>
                    <Section title="Attack classification">
                      {result.gemini.classification}
                    </Section>
                    <Section title="Root cause">{result.gemini.rootCause}</Section>

                    <Section title="Evidence">
                      <ul className="flex flex-col gap-1.5">
                        {result.gemini.evidence.map((line) => (
                          <li key={line} className="text-[12.5px] text-muted-foreground">
                            {line}
                          </li>
                        ))}
                      </ul>
                    </Section>

                    <Section title="MITRE ATT&CK mapping">
                      <ul className="flex flex-col gap-2">
                        {result.gemini.mitre.map((item) => (
                          <li key={`${item.id}-${item.technique}`} className="flex flex-wrap items-baseline gap-2">
                            <span className="font-mono text-[12px] font-semibold">{item.id}</span>
                            <span className="text-[12.5px]">{item.tactic}</span>
                            <span className="text-[12.5px] text-muted-foreground">
                              — {item.technique}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </Section>

                    <Section title="Impact assessment">{result.gemini.impact}</Section>

                    <Section title="Risk factors" tone="critical">
                      <div className="flex flex-col gap-2.5">
                        {result.gemini.risks.map((risk) => (
                          <div key={risk.label} className="flex items-center gap-3">
                            <span className="w-40 shrink-0 text-[12.5px]">{risk.label}</span>
                            <ConfidenceBar value={risk.score / 100} tone="critical" />
                            <span className="w-9 text-right text-[12px] tabular-nums">
                              {risk.score}%
                            </span>
                          </div>
                        ))}
                      </div>
                    </Section>

                    <Section title="Recommended containment" tone="warning">
                      {result.gemini.containment}
                    </Section>
                    <Section title="Recommended remediation">
                      {result.gemini.remediation}
                    </Section>
                    <Section title="Why the model believes this">
                      {result.gemini.confidenceExplanation}
                    </Section>

                    <Section title="Alternative actions">
                      <ul className="flex flex-col divide-y divide-border/60">
                        {result.gemini.alternatives.map((alt) => (
                          <li key={alt.action} className="flex items-start justify-between gap-4 py-2.5">
                            <span className="text-[12.5px]">
                              <span className="font-semibold">{alt.action}</span> — {alt.note}
                            </span>
                            <span className="shrink-0 text-[11.5px] text-muted-foreground tabular-nums">
                              viability {alt.viability}%
                            </span>
                          </li>
                        ))}
                      </ul>
                    </Section>

                    {result.gemini.remediationCode && (
                      <Section title="Remediation snippet" tone="warning">
                        <div className="mt-1 overflow-hidden rounded-lg border">
                          <div className="flex items-center justify-between gap-3 border-b bg-muted/60 px-3 py-2">
                            <span className="text-[9.5px] font-semibold tracking-[0.14em] text-[var(--signal-warning)] uppercase">
                              Simulation / human review required
                            </span>
                            <button
                              type="button"
                              onClick={copyCode}
                              className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] text-muted-foreground transition-colors hover:text-foreground"
                            >
                              <Copy className="size-3.5" />
                              {copied ? "Copied" : "Copy"}
                            </button>
                          </div>
                          <pre className="overflow-x-auto bg-muted/30 p-3 font-mono text-[11.5px] leading-relaxed whitespace-pre-wrap">
                            {result.gemini.remediationCode}
                          </pre>
                        </div>
                        <p className="mt-2 text-[11.5px] text-muted-foreground">
                          Never executed automatically. Generated scripts always require analyst
                          sign-off.
                        </p>
                      </Section>
                    )}
                  </motion.div>
                ) : null}
              </TabsContent>

              {/* ---------------- REVIEW ---------------- */}
              <TabsContent value="review" className="flex flex-col gap-6 px-5 py-6">
                <Section title="Decision matrix" tone="neutral">
                  <p className="mb-3 text-[12.5px] text-muted-foreground">
                    Every eligible action scored against the current posture. The engine's pick is
                    highlighted.
                  </p>
                  <DecisionMatrix rows={result.decision.ranked} />
                </Section>

                <Section title="Analyst review" tone="neutral">
                  {!canReview ? (
                    <div className="rounded-lg border bg-muted/50 px-4 py-3 text-[12.5px] text-muted-foreground">
                      Your role is <strong>{user?.role ?? "VIEWER"}</strong>. Viewer access is
                      read-only — decisions require SOC_ANALYST or ADMIN.
                    </div>
                  ) : result.reviewStatus !== "PENDING" ? (
                    <div className="rounded-lg border border-[var(--signal-info-line)] bg-[var(--signal-info-bg)] px-4 py-3">
                      <p className="text-[13px] font-semibold">
                        {result.reviewStatus} by {result.reviewedBy}
                      </p>
                      <p className="mt-1 text-[12.5px] text-muted-foreground">
                        {result.reviewNote || "No note recorded."}
                      </p>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-4">
                      <div className="flex flex-col gap-1.5">
                        <Label htmlFor="review-note" className="text-[11px] tracking-[0.1em] uppercase">
                          Analyst note
                        </Label>
                        <Input
                          id="review-note"
                          value={note}
                          onChange={(event) => setNote(event.target.value)}
                          placeholder="Why are you confirming or changing this decision?"
                          className="h-9"
                        />
                      </div>

                      <div className="flex flex-col gap-1.5">
                        <Label htmlFor="override-action" className="text-[11px] tracking-[0.1em] uppercase">
                          Override action
                        </Label>
                        <select
                          id="override-action"
                          value={override}
                          onChange={(event) => setOverride(event.target.value)}
                          className="h-9 w-full cursor-pointer rounded-md border border-input bg-background px-3 text-[13px] outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
                        >
                          <option value="">Use the engine recommendation</option>
                          {Object.keys(ACTION_PROFILE).map((action) => (
                            <option key={action} value={action}>
                              {action} — {ACTION_PROFILE[action as keyof typeof ACTION_PROFILE].short}
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <Button size="sm" onClick={() => submit("APPROVED")}>
                          <ShieldCheck className="size-4" />
                          Approve recommendation
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={!override}
                          onClick={() => submit("OVERRIDDEN")}
                        >
                          <Gavel className="size-4" />
                          Record override
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => submit("DISMISSED")}
                        >
                          Mark false positive
                        </Button>
                      </div>
                      {!override && (
                        <p className="text-[11.5px] text-muted-foreground">
                          Choose an override action to enable the override button.
                        </p>
                      )}
                    </div>
                  )}
                </Section>

                <Section title="Audit history" tone="neutral">
                  {entries.length === 0 ? (
                    <p className="text-[12.5px] text-muted-foreground">
                      No audit entries for this event yet.
                    </p>
                  ) : (
                    <ul className="flex flex-col divide-y divide-border/60">
                      {entries.map((entry) => (
                        <li key={entry.id} className="flex flex-wrap gap-x-3 gap-y-0.5 py-2 text-[12px]">
                          <span className="w-36 shrink-0 text-muted-foreground tabular-nums">
                            {new Date(entry.timestamp).toLocaleTimeString()}
                          </span>
                          <span className="w-28 shrink-0 font-medium">{entry.action}</span>
                          <span className="min-w-0 flex-1 text-muted-foreground">
                            {entry.detail}
                          </span>
                          <span className="text-muted-foreground/70">{entry.actor}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="mt-3 text-[11.5px] text-muted-foreground">
                    <FileSearch className="mr-1 inline size-3.5" />
                    The audit trail is append-only and cannot be edited from the interface.
                  </p>
                </Section>
              </TabsContent>
            </Tabs>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: Tone;
}) {
  return (
    <div className="flex flex-col gap-1 bg-background px-4 py-3">
      <span className="text-[10px] tracking-[0.14em] text-muted-foreground uppercase">
        {label}
      </span>
      <span
        className={cn(
          "text-xl leading-none font-semibold tracking-tight tabular-nums",
          tone && TEXT_TONE[tone],
        )}
      >
        {value}
      </span>
    </div>
  );
}
