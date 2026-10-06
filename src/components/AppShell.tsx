import { Mark } from "@/components/Mark";
import { Chip } from "@/components/chips";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth } from "@/hooks/use-auth";
import type { QueueMetrics } from "@/core";
import { cn } from "@/lib/utils";
import { Activity, ClipboardList, Gauge, LogOut, Menu, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router";

export type ConsoleView = "queue" | "audit";

const NAV: Array<{ id: ConsoleView; label: string; icon: typeof Activity }> = [
  { id: "queue", label: "Triage Queue", icon: Activity },
  { id: "audit", label: "Audit Trail", icon: ClipboardList },
];

function StatusCard({ metrics, efficiency }: { metrics: QueueMetrics; efficiency: number }) {
  const rows: Array<[string, string]> = [
    ["Uptime", "99.98%"],
    ["Active servers", "50"],
    ["Threats detected", metrics.ingested.toLocaleString()],
    ["Threats contained", metrics.contained.toLocaleString()],
    ["Gemini escalations", metrics.geminiCalls.toLocaleString()],
    ["Avg. triage latency", `${metrics.avgTotalLatencyMs} ms`],
    ["Deep calls avoided", `${efficiency}%`],
  ];
  return (
    <div className="border-t px-4 py-4">
      <div className="flex items-center gap-2">
        <span className="size-1.5 rounded-full bg-[var(--signal-safe)] pulse-dot" />
        <span className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
          System status
        </span>
      </div>
      <p className="mt-1.5 text-[12.5px] font-medium">All systems operational</p>
      <dl className="mt-3 flex flex-col gap-1.5">
        {rows.map(([label, value]) => (
          <div key={label} className="flex items-baseline justify-between gap-2">
            <dt className="text-[11.5px] text-muted-foreground">{label}</dt>
            <dd className="text-[11.5px] font-medium tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

export function AppShell({
  view,
  onView,
  metrics,
  efficiency,
  aiMode,
  degraded,
  children,
}: {
  view: ConsoleView;
  onView: (view: ConsoleView) => void;
  metrics: QueueMetrics;
  efficiency: number;
  aiMode: "LIVE" | "DEMO_FIXTURE";
  degraded: boolean;
  children: ReactNode;
}) {
  const { user, signOut, mode } = useAuth();
  const navigate = useNavigate();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const nav = (
    <nav className="flex flex-col gap-0.5">
      {NAV.map((item) => {
        const active = view === item.id;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => {
              onView(item.id);
              setMobileNavOpen(false);
            }}
            className={cn(
              "flex cursor-pointer items-center gap-2.5 rounded-md px-3 py-2 text-left text-[13px] transition-colors",
              active
                ? "bg-foreground text-background font-medium"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
            )}
          >
            <item.icon className="size-4" />
            {item.label}
          </button>
        );
      })}
    </nav>
  );

  return (
    <div className="flex min-h-screen bg-background">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r bg-background lg:flex">
        <div className="flex items-center gap-2.5 px-4 py-4">
          <Mark className="size-5" />
          <div className="leading-none">
            <div className="text-[12.5px] font-semibold tracking-[0.14em] uppercase">
              CyberSentinel
            </div>
            <div className="mt-1 text-[10px] tracking-[0.14em] text-muted-foreground uppercase">
              Probabilistic SOC
            </div>
          </div>
        </div>

        <div className="px-3 pt-2 pb-3">
          <div className="mb-2 px-3 text-[10px] tracking-[0.16em] text-muted-foreground/70 uppercase">
            Operations
          </div>
          {nav}
        </div>

        <div className="mt-auto">
          <StatusCard metrics={metrics} efficiency={efficiency} />
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="sticky top-0 z-20 border-b bg-background/95 backdrop-blur">
          <div className="flex h-14 items-center gap-3 px-4 sm:px-6">
            <button
              type="button"
              className="cursor-pointer rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground lg:hidden"
              onClick={() => setMobileNavOpen((open) => !open)}
              aria-label="Toggle navigation"
            >
              {mobileNavOpen ? <X className="size-5" /> : <Menu className="size-5" />}
            </button>

            <div className="hidden items-center gap-2.5 lg:flex">
              <Mark className="size-4" />
              <span className="text-[13px] font-semibold tracking-tight">
                CyberSentinel v2.0
              </span>
              <span className="text-[11px] text-muted-foreground">The Probabilistic SOC Copilot</span>
            </div>

            <div className="ml-auto flex items-center gap-2">
              <Chip tone={aiMode === "LIVE" ? "safe" : "ai"} title="Which engine produced the numbers on screen">
                {aiMode === "LIVE" ? "AI MODE · LIVE" : "AI MODE · DEMO FIXTURE"}
              </Chip>
              <Chip tone={mode === "backend" && !degraded ? "info" : "warning"}>
                {mode === "backend" && !degraded ? "API CONNECTED" : "LOCAL ENGINE"}
              </Chip>

              <span className="hidden items-center gap-1.5 text-[11px] tracking-[0.1em] text-muted-foreground uppercase sm:flex">
                <span className="size-1.5 rounded-full bg-[var(--signal-safe)] pulse-dot" />
                Operational
              </span>

              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="sm" className="gap-2">
                    <span className="flex size-6 items-center justify-center rounded-full bg-foreground text-[10px] font-semibold text-background">
                      {(user?.name ?? "A").slice(0, 1).toUpperCase()}
                    </span>
                    <span className="hidden max-w-28 truncate text-[12.5px] sm:inline">
                      {user?.name ?? "Analyst"}
                    </span>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <DropdownMenuLabel className="truncate">
                    {user?.email}
                  </DropdownMenuLabel>
                  <div className="px-2 pb-2">
                    <Chip tone="neutral">{user?.role ?? "VIEWER"}</Chip>
                  </div>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => navigate("/")} className="cursor-pointer">
                    <Gauge className="size-4" />
                    Product overview
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={handleSignOut}
                    className="cursor-pointer text-destructive focus:text-destructive"
                  >
                    <LogOut className="size-4" />
                    Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>

          {mobileNavOpen && (
            <div className="border-t px-4 py-3 lg:hidden">{nav}</div>
          )}
        </header>

        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  );
}
