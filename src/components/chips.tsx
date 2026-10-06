import type { AiMode, ReviewStatus, RouteKind, ServerStatus } from "@/core";
import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

/**
 * The only colour in the product. Every other pixel is paper and ink, so these
 * tones carry real meaning: red = hostile, amber = unresolved, green = safe,
 * blue = telemetry, violet = model reasoning.
 */
export const TONE = {
  critical:
    "text-[var(--signal-critical)] bg-[var(--signal-critical-bg)] border-[var(--signal-critical-line)]",
  warning:
    "text-[var(--signal-warning)] bg-[var(--signal-warning-bg)] border-[var(--signal-warning-line)]",
  safe: "text-[var(--signal-safe)] bg-[var(--signal-safe-bg)] border-[var(--signal-safe-line)]",
  info: "text-[var(--signal-info)] bg-[var(--signal-info-bg)] border-[var(--signal-info-line)]",
  ai: "text-[var(--signal-ai)] bg-[var(--signal-ai-bg)] border-[var(--signal-ai-line)]",
  neutral: "text-muted-foreground bg-muted border-border",
} as const;

export type Tone = keyof typeof TONE;

/** Text-only variants — for headings and numerals that should carry a state. */
export const TEXT_TONE: Record<Tone, string> = {
  critical: "text-[var(--signal-critical)]",
  warning: "text-[var(--signal-warning)]",
  safe: "text-[var(--signal-safe)]",
  info: "text-[var(--signal-info)]",
  ai: "text-[var(--signal-ai)]",
  neutral: "text-foreground",
};

export function toneForRoute(route: RouteKind): Tone {
  if (route === "CONTAIN") return "critical";
  if (route === "DISMISS") return "safe";
  return "warning";
}

export function routeLabel(route: RouteKind): string {
  if (route === "CONTAIN") return "CONTAIN";
  if (route === "DISMISS") return "DISMISS";
  return "ESCALATE";
}

export function toneForServer(status: ServerStatus): Tone {
  switch (status) {
    case "ISOLATED":
      return "critical";
    case "COMPROMISED":
      return "critical";
    case "INVESTIGATING":
    case "THROTTLED":
      return "warning";
    case "MONITORING":
      return "info";
    default:
      return "safe";
  }
}

export function toneForReview(status: ReviewStatus): Tone {
  if (status === "APPROVED") return "safe";
  if (status === "OVERRIDDEN") return "info";
  if (status === "DISMISSED") return "neutral";
  return "warning";
}

export function Chip({
  tone = "neutral",
  children,
  className,
  pulse = false,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  pulse?: boolean;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex w-fit items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold tracking-[0.1em] whitespace-nowrap",
        TONE[tone],
        className,
      )}
    >
      {pulse && (
        <span className="size-1.5 shrink-0 rounded-full bg-current pulse-dot" />
      )}
      {children}
    </span>
  );
}

/** Thin confidence bar — used wherever the engine reports a percentage. */
export function ConfidenceBar({
  value,
  tone = "neutral",
  className,
}: {
  value: number;
  tone?: Tone;
  className?: string;
}) {
  const pct = Math.round(Math.min(100, Math.max(0, value * 100)));
  const fill: Record<Tone, string> = {
    critical: "bg-[var(--signal-critical)]",
    warning: "bg-[var(--signal-warning)]",
    safe: "bg-[var(--signal-safe)]",
    info: "bg-[var(--signal-info)]",
    ai: "bg-[var(--signal-ai)]",
    neutral: "bg-foreground/70",
  };
  return (
    <div
      className={cn("h-1 w-full overflow-hidden rounded-full bg-muted", className)}
      role="progressbar"
      aria-valuenow={pct}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className={cn("h-full rounded-full transition-[width] duration-700", fill[tone])}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

export function LatencyBadge({
  ms,
  label,
  className,
}: {
  ms: number;
  label: string;
  className?: string;
}) {
  if (ms <= 0) {
    return (
      <span
        className={cn(
          "text-[11px] tracking-[0.08em] text-muted-foreground uppercase tabular-nums",
          className,
        )}
      >
        — not called
      </span>
    );
  }
  return (
    <span className={cn("inline-flex items-baseline gap-1.5 tabular-nums", className)}>
      <span className="text-[11px] tracking-[0.1em] text-muted-foreground uppercase">
        {label}
      </span>
      <span className="text-[13px] font-semibold">{ms} ms</span>
    </span>
  );
}

export function AiModeChip({ source }: { source: AiMode | "LIVE" }) {
  return source === "LIVE" ? (
    <Chip tone="safe" pulse title="Live model responses from the configured backend">
      AI MODE · LIVE
    </Chip>
  ) : (
    <Chip tone="ai" title="Deterministic fixtures — no external model call was made">
      AI MODE · DEMO FIXTURE
    </Chip>
  );
}
