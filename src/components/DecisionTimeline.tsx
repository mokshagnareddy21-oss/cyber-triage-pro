import { Chip, ConfidenceBar, type Tone } from "@/components/chips";
import type { TimelineStep } from "@/core";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";

const MARKER_TONE: Record<TimelineStep["tone"], Tone> = {
  neutral: "neutral",
  critical: "critical",
  warning: "warning",
  safe: "safe",
  ai: "ai",
};

const RING: Record<TimelineStep["tone"], string> = {
  neutral: "border-border",
  critical: "border-[var(--signal-critical-line)] bg-[var(--signal-critical-bg)]",
  warning: "border-[var(--signal-warning-line)] bg-[var(--signal-warning-bg)]",
  safe: "border-[var(--signal-safe-line)] bg-[var(--signal-safe-bg)]",
  ai: "border-[var(--signal-ai-line)] bg-[var(--signal-ai-bg)]",
};

const DOT: Record<TimelineStep["tone"], string> = {
  neutral: "bg-muted-foreground",
  critical: "bg-[var(--signal-critical)]",
  warning: "bg-[var(--signal-warning)]",
  safe: "bg-[var(--signal-safe)]",
  ai: "bg-[var(--signal-ai)]",
};

/**
 * The decision timeline: every step the system took, how confident it was, and
 * what it cost. This is the single most important artefact in the product —
 * it is how a judge sees *reasoning* rather than a verdict.
 */
export function DecisionTimeline({
  steps,
  animateKey,
  className,
}: {
  steps: TimelineStep[];
  /** Change this to replay the entrance animation for a newly selected event. */
  animateKey?: string;
  className?: string;
}) {
  return (
    <ol className={cn("relative flex flex-col", className)}>
      <span
        aria-hidden
        className="absolute top-3 bottom-3 left-[7px] w-px bg-border"
      />
      {steps.map((step, index) => (
        <motion.li
          key={`${animateKey ?? "step"}-${step.key}`}
          initial={{ opacity: 0, x: -6 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.32, delay: Math.min(index * 0.07, 0.5), ease: "easeOut" }}
          className="relative flex gap-3.5 pb-5 last:pb-0"
        >
          <span
            aria-hidden
            className={cn(
              "relative z-10 mt-1 flex size-[15px] shrink-0 items-center justify-center rounded-full border",
              RING[step.tone],
              step.state === "skipped" && "border-dashed bg-background",
              step.state === "failed" && "border-[var(--signal-critical-line)]",
            )}
          >
            <span
              className={cn(
                "size-1.5 rounded-full",
                step.state === "skipped" ? "bg-border" : DOT[step.tone],
              )}
            />
          </span>

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <h4
                className={cn(
                  "text-[13px] leading-tight font-semibold tracking-tight",
                  step.state === "skipped" && "text-muted-foreground line-through",
                  step.state === "failed" && "text-[var(--signal-critical)]",
                )}
              >
                {step.label}
              </h4>
              {step.caption && (
                <Chip tone={MARKER_TONE[step.tone]} className="px-1.5 py-0 text-[9.5px]">
                  {step.caption}
                </Chip>
              )}
            </div>

            <p className="mt-1 text-[12.5px] leading-relaxed text-muted-foreground">
              {step.detail}
            </p>

            {(step.confidence !== undefined || step.latencyMs !== undefined) && (
              <div className="mt-2 flex items-center gap-3">
                {step.confidence !== undefined && (
                  <div className="flex min-w-32 flex-1 items-center gap-2">
                    <ConfidenceBar
                      value={step.confidence}
                      tone={MARKER_TONE[step.tone]}
                      className="max-w-36"
                    />
                    <span className="text-[11px] font-medium tabular-nums">
                      {Math.round(step.confidence * 100)}%
                    </span>
                    <span className="text-[10px] tracking-[0.1em] text-muted-foreground uppercase">
                      confidence
                    </span>
                  </div>
                )}
                {step.latencyMs !== undefined && step.latencyMs > 0 && (
                  <span className="text-[11px] tabular-nums text-muted-foreground">
                    {step.latencyMs} ms
                  </span>
                )}
              </div>
            )}
          </div>
        </motion.li>
      ))}
    </ol>
  );
}
