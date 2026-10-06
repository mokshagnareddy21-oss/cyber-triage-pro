import { AppShell, type ConsoleView } from "@/components/AppShell";
import { Chip, ConfidenceBar, routeLabel, toneForReview, toneForRoute } from "@/components/chips";
import { IncidentDrawer } from "@/components/IncidentDrawer";
import { MetricCard } from "@/components/MetricCard";
import { SCENARIOS, type RouteKind, type TriageResult } from "@/core";
import { useTriage } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";
import {
  ChevronRight,
  Pause,
  Play,
  RotateCcw,
  Search,
  StepForward,
  TriangleAlert,
} from "lucide-react";
import { useMemo, useState } from "react";

const ROUTE_FILTERS: Array<{ id: "ALL" | RouteKind; label: string }> = [
  { id: "ALL", label: "All routes" },
  { id: "CONTAIN", label: "Contain" },
  { id: "GRAY", label: "Escalate" },
  { id: "DISMISS", label: "Dismiss" },
];

function humanise(value: string): string {
  return value.split("_").join(" ");
}

function QueueTable({
  rows,
  onOpen,
}: {
  rows: TriageResult[];
  onOpen: (id: string) => void;
}) {
  if (rows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 border-y border-dashed px-6 py-16 text-center">
        <Search className="size-5 text-muted-foreground" />
        <p className="text-sm font-medium">No events match this filter</p>
        <p className="max-w-sm text-[12.5px] text-muted-foreground">
          Adjust the route filter or search term, or let the stream run to ingest fresh events.
        </p>
      </div>
    );
  }

  return (
    <div className="w-full overflow-x-auto">
      <table className="w-full min-w-[940px] text-left text-[12.5px]">
        <thead>
          <tr className="border-b text-[10px] tracking-[0.12em] text-muted-foreground uppercase">
            <th className="py-2.5 pr-3 font-medium">Time</th>
            <th className="py-2.5 pr-3 font-medium">Event</th>
            <th className="py-2.5 pr-3 font-medium">Server</th>
            <th className="py-2.5 pr-3 font-medium">Signal</th>
            <th className="py-2.5 pr-3 font-medium">Probability</th>
            <th className="py-2.5 pr-3 font-medium">Sev</th>
            <th className="py-2.5 pr-3 font-medium">Route</th>
            <th className="py-2.5 pr-3 font-medium">Decision</th>
            <th className="py-2.5 pr-3 font-medium">Latency</th>
            <th className="py-2.5 pr-3 font-medium">Review</th>
            <th className="py-2.5 pr-3 font-medium" aria-label="Open" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <motion.tr
              key={row.event.id}
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.28, delay: Math.min(index * 0.012, 0.2) }}
              onClick={() => onOpen(row.event.id)}
              className={cn(
                "cursor-pointer border-b border-border/60 transition-colors last:border-b-0 hover:bg-muted/60",
                row.reviewStatus === "PENDING" && "bg-transparent",
              )}
            >
              <td className="py-2.5 pr-3 text-muted-foreground tabular-nums">
                {new Date(row.event.timestamp).toLocaleTimeString([], { hour12: false })}
              </td>
              <td className="py-2.5 pr-3 font-mono text-[11.5px]">{row.event.id}</td>
              <td className="py-2.5 pr-3 font-medium">{row.event.serverId}</td>
              <td className="max-w-56 truncate py-2.5 pr-3 text-muted-foreground">
                {humanise(row.event.eventType)}
              </td>
              <td className="py-2.5 pr-3">
                <span className="flex items-center gap-2">
                  <span className="w-9 font-semibold tabular-nums">
                    {row.jev.maliciousProbability.toFixed(2)}
                  </span>
                  <span className="w-16">
                    <ConfidenceBar
                      value={row.jev.maliciousProbability}
                      tone={toneForRoute(row.route)}
                    />
                  </span>
                </span>
              </td>
              <td className="py-2.5 pr-3 tabular-nums">{row.jev.severityScore}</td>
              <td className="py-2.5 pr-3">
                <Chip tone={toneForRoute(row.route)}>{routeLabel(row.route)}</Chip>
              </td>
              <td className="py-2.5 pr-3 font-semibold">{row.decision.action}</td>
              <td className="py-2.5 pr-3 text-muted-foreground tabular-nums">
                {row.latency.totalMs} ms
              </td>
              <td className="py-2.5 pr-3">
                <Chip tone={toneForReview(row.reviewStatus)}>{row.reviewStatus}</Chip>
              </td>
              <td className="py-2.5 pr-3 text-muted-foreground">
                <ChevronRight className="size-4" />
              </td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Console() {
  const {
    results,
    metrics,
    efficiency,
    audit,
    streaming,
    speedMs,
    setSpeed,
    startStream,
    stopStream,
    step,
    reset,
    select,
    degraded,
    transport,
    aiMode,
  } = useTriage();
  const [view, setView] = useState<ConsoleView>("queue");
  const [routeFilter, setRouteFilter] = useState<"ALL" | RouteKind>("ALL");
  const [query, setQuery] = useState("");
  const [scenario, setScenario] = useState("");

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return results.filter((row) => {
      if (routeFilter !== "ALL" && row.route !== routeFilter) return false;
      if (!needle) return true;
      return (
        row.event.id.toLowerCase().includes(needle) ||
        row.event.serverId.toLowerCase().includes(needle) ||
        row.event.eventType.toLowerCase().includes(needle) ||
        row.event.payload.toLowerCase().includes(needle) ||
        row.decision.action.toLowerCase().includes(needle)
      );
    });
  }, [results, routeFilter, query]);

  const handleScenario = async (key: string) => {
    setScenario("");
    if (!key) return;
    await step(key);
  };

  return (
    <>
      <AppShell
        view={view}
        onView={setView}
        metrics={metrics}
        efficiency={efficiency}
        aiMode={aiMode}
        degraded={degraded}
      >
        {view === "queue" ? (
          <div className="flex flex-col">
            {/* ---- Metric strip ---- */}
            <div className="grid grid-cols-2 gap-px border-b bg-border sm:grid-cols-3 xl:grid-cols-6">
              <MetricCard
                label="Threats detected"
                value={metrics.ingested}
                hint="events ingested"
              />
              <MetricCard
                label="Auto-contained"
                value={metrics.contained}
                accent="text-[var(--signal-critical)]"
                hint="p > 0.95"
              />
              <MetricCard
                label="Gray-zone events"
                value={metrics.grayZone}
                accent="text-[var(--signal-warning)]"
                hint="0.40 ≤ p ≤ 0.95"
              />
              <MetricCard
                label="False positives avoided"
                value={metrics.dismissed}
                accent="text-[var(--signal-safe)]"
                hint="p < 0.40"
              />
              <MetricCard
                label="Gemini escalations"
                value={metrics.geminiCalls}
                accent="text-[var(--signal-ai)]"
                hint={`${metrics.geminiCallsAvoided} deep calls avoided`}
              />
              <MetricCard
                label="Avg. triage latency"
                value={metrics.avgTotalLatencyMs}
                suffix="ms"
                hint={`${metrics.avgJevLatencyMs} ms fast pass · demo simulation`}
              />
            </div>

            {/* ---- Routing efficiency band ---- */}
            <div className="flex flex-wrap items-center gap-x-8 gap-y-3 border-b bg-muted/40 px-4 py-3 sm:px-6">
              <span className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
                LLM routing efficiency
              </span>
              <Fact label="Events" value={metrics.ingested.toLocaleString()} />
              <Fact label="Jev triaged" value={metrics.ingested.toLocaleString()} />
              <Fact label="Gemini calls" value={metrics.geminiCalls.toLocaleString()} />
              <Fact
                label="Potential calls avoided"
                value={`${metrics.geminiCallsAvoided.toLocaleString()} · ${efficiency}%`}
                tone="safe"
              />
              <span className="ml-auto hidden text-[11px] text-muted-foreground md:inline">
                Calculated from live queue data — not a hardcoded figure.
              </span>
            </div>

            {degraded && (
              <div className="flex items-start gap-2 border-b border-[var(--signal-warning-line)] bg-[var(--signal-warning-bg)] px-4 py-2.5 text-[12.5px] sm:px-6">
                <TriangleAlert className="mt-0.5 size-4 shrink-0 text-[var(--signal-warning)]" />
                <span>
                  The decision API is unreachable, so the console is running the local
                  deterministic engine. Decisions are real; the model outputs are labelled{" "}
                  <strong>DEMO FIXTURE</strong>.
                </span>
              </div>
            )}

            {/* ---- Controls ---- */}
            <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3 sm:px-6">
              <Button
                size="sm"
                variant={streaming ? "outline" : "default"}
                onClick={() => (streaming ? stopStream() : startStream())}
                className="gap-1.5"
              >
                {streaming ? <Pause className="size-4" /> : <Play className="size-4" />}
                {streaming ? "Pause stream" : "Resume stream"}
              </Button>

              <Button
                size="sm"
                variant="outline"
                onClick={() => void step()}
                className="gap-1.5"
              >
                <StepForward className="size-4" />
                Ingest one event
              </Button>

              <select
                value={speedMs}
                onChange={(event) => setSpeed(Number(event.target.value))}
                aria-label="Stream speed"
                className="h-8 cursor-pointer rounded-md border border-input bg-background px-2 text-[12.5px] outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
              >
                <option value={1200}>Fast · 1.2 s</option>
                <option value={2600}>Normal · 2.6 s</option>
                <option value={5000}>Slow · 5 s</option>
              </select>

              <select
                value={scenario}
                onChange={(event) => void handleScenario(event.target.value)}
                aria-label="Run a demo scenario"
                className="h-8 cursor-pointer rounded-md border border-input bg-background px-2 text-[12.5px] outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
              >
                <option value="">Run a scenario…</option>
                {SCENARIOS.map((entry) => (
                  <option key={entry.key} value={entry.key}>
                    {entry.name} → {entry.expectedRoute} / {entry.expectedAction}
                  </option>
                ))}
              </select>

              <Button size="sm" variant="ghost" onClick={reset} className="gap-1.5">
                <RotateCcw className="size-4" />
                Reset
              </Button>

              <div className="ml-auto flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute top-2.5 left-2.5 size-3.5 text-muted-foreground" />
                  <Input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search event, server, payload…"
                    className="h-8 w-56 pl-8 text-[12.5px]"
                  />
                </div>
                <div className="flex items-center gap-1 rounded-md border p-0.5">
                  {ROUTE_FILTERS.map((filter) => (
                    <button
                      key={filter.id}
                      type="button"
                      onClick={() => setRouteFilter(filter.id)}
                      className={cn(
                        "cursor-pointer rounded px-2.5 py-1 text-[11.5px] transition-colors",
                        routeFilter === filter.id
                          ? "bg-foreground font-medium text-background"
                          : "text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {filter.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* ---- Queue ---- */}
            <div className="flex items-center justify-between gap-3 px-4 py-3 sm:px-6">
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "size-1.5 rounded-full",
                    streaming
                      ? "bg-[var(--signal-critical)] pulse-dot"
                      : "bg-muted-foreground",
                  )}
                />
                <h2 className="text-[13px] font-semibold tracking-tight">
                  Live event triage queue
                </h2>
                <span className="text-[11.5px] text-muted-foreground">
                  {rows.length} of {results.length} events
                </span>
              </div>
              <span className="text-[11px] tracking-[0.1em] text-muted-foreground uppercase">
                {transport === "backend" && !degraded ? "Express API" : "Local engine"} ·
                streaming {streaming ? "on" : "off"}
              </span>
            </div>

            <div className="border-t">
              <QueueTable rows={rows} onOpen={(id) => select(id)} />
            </div>

            <p className="px-4 py-4 text-[11.5px] text-muted-foreground sm:px-6">
              Containment, isolation and throttling are simulated state changes on synthetic
              infrastructure. No real host is ever touched.
            </p>
          </div>
        ) : (
          <div className="flex flex-col">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-4 sm:px-6">
              <div>
                <h2 className="text-[15px] font-semibold tracking-tight">Audit trail</h2>
                <p className="text-[12.5px] text-muted-foreground">
                  Append-only record of every ingest, triage, route, recommendation and analyst
                  review.
                </p>
              </div>
              <Chip tone="neutral">IMMUTABLE FROM UI</Chip>
            </div>

            <div className="w-full overflow-x-auto">
              <table className="w-full min-w-[860px] text-left text-[12.5px]">
                <thead>
                  <tr className="border-b text-[10px] tracking-[0.12em] text-muted-foreground uppercase">
                    <th className="py-2.5 pr-3 font-medium">Timestamp</th>
                    <th className="py-2.5 pr-3 font-medium">Actor</th>
                    <th className="py-2.5 pr-3 font-medium">Action</th>
                    <th className="py-2.5 pr-3 font-medium">Event</th>
                    <th className="py-2.5 pr-3 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.slice(0, 200).map((entry) => (
                    <tr
                      key={entry.id}
                      className="border-b border-border/60 last:border-b-0"
                    >
                      <td className="py-2 pr-3 text-muted-foreground tabular-nums">
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td className="py-2 pr-3">{entry.actor}</td>
                      <td className="py-2 pr-3">
                        <span className="font-mono text-[11.5px] font-medium">
                          {entry.action}
                        </span>
                      </td>
                      <td className="py-2 pr-3 font-mono text-[11.5px] text-muted-foreground">
                        {entry.eventId}
                      </td>
                      <td className="py-2 pr-3 text-muted-foreground">{entry.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="px-4 py-4 text-[11.5px] text-muted-foreground sm:px-6">
              Showing the {Math.min(200, audit.length)} most recent of {audit.length} entries.
            </p>
          </div>
        )}
      </AppShell>
      <IncidentDrawer />
    </>
  );
}

function Fact({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "safe";
}) {
  return (
    <span className="flex items-baseline gap-2">
      <span className="text-[11px] text-muted-foreground">{label}</span>
      <span
        className={cn(
          "text-[12.5px] font-semibold tabular-nums",
          tone === "safe" && "text-[var(--signal-safe)]",
        )}
      >
        {value}
      </span>
    </span>
  );
}
