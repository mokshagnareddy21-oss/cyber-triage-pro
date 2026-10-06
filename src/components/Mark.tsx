import { cn } from "@/lib/utils";

/** CyberSentinel's mark: a crosshair inside a bounded frame. Monochrome by design. */
export function Mark({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className={cn("size-6", className)}
    >
      <rect
        x="2.75"
        y="2.75"
        width="18.5"
        height="18.5"
        rx="5"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M12 2.75v3.5M12 17.75v3.5M2.75 12h3.5M17.75 12h3.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="12" cy="12" r="3.1" fill="currentColor" />
    </svg>
  );
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      <Mark className="size-5" />
      <span className="text-[13px] font-semibold tracking-[0.16em] uppercase">
        CyberSentinel
      </span>
      <span className="text-[11px] font-medium tracking-[0.12em] text-muted-foreground tabular-nums">
        v2.0
      </span>
    </span>
  );
}
