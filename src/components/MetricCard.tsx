import { cn } from "@/lib/utils";
import { useEffect, useRef, useState } from "react";

/** Animated counter — values ease rather than jump when the queue updates. */
export function useCountUp(value: number, duration = 650): number {
  const [display, setDisplay] = useState(value);
  const displayRef = useRef(value);

  useEffect(() => {
    const from = displayRef.current;
    if (from === value) return;
    const start = performance.now();
    let frame = 0;

    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      const next = Math.round(from + (value - from) * eased);
      displayRef.current = next;
      setDisplay(next);
      if (progress < 1) frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value, duration]);

  return display;
}

export function MetricCard({
  label,
  value,
  suffix,
  hint,
  accent = "text-foreground",
  className,
}: {
  label: string;
  value: number;
  suffix?: string;
  hint?: string;
  accent?: string;
  className?: string;
}) {
  const animated = useCountUp(value);
  return (
    <div className={cn("flex min-w-0 flex-col gap-1 px-4 py-3.5", className)}>
      <span className="text-[10px] font-medium tracking-[0.14em] text-muted-foreground uppercase">
        {label}
      </span>
      <span className={cn("text-2xl leading-none font-semibold tracking-tight tabular-nums", accent)}>
        {animated.toLocaleString()}
        {suffix && <span className="ml-0.5 text-sm font-medium">{suffix}</span>}
      </span>
      {hint && (
        <span className="truncate text-[11px] leading-tight text-muted-foreground">{hint}</span>
      )}
    </div>
  );
}
