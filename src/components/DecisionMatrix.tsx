import type { ScoredAction } from "@/core";
import { cn } from "@/lib/utils";

/**
 * The action matrix: what each response costs, what it buys, and which one the
 * engine picked. Selected row is marked by a rule, not by a colour wash — the
 * palette stays monochrome except for the recommendation chip.
 */
export function DecisionMatrix({
  rows,
  selected,
  onSelect,
  className,
}: {
  rows: ScoredAction[];
  selected?: string;
  onSelect?: (action: string) => void;
  className?: string;
}) {
  return (
    <div className={cn("w-full overflow-x-auto", className)}>
      <table className="w-full text-left text-[12.5px]">
        <thead>
          <tr className="border-b text-[10px] tracking-[0.12em] text-muted-foreground uppercase">
            <th className="py-2 pr-3 font-medium">Action</th>
            <th className="py-2 pr-3 font-medium">Containment</th>
            <th className="py-2 pr-3 font-medium">Disruption</th>
            <th className="py-2 pr-3 font-medium">Speed</th>
            <th className="py-2 pr-3 font-medium">Cost</th>
            <th className="py-2 pr-3 font-medium">Exposure</th>
            <th className="py-2 pr-3 text-right font-medium">Fit</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const isSelected = row.selected || row.action === selected;
            return (
              <tr
                key={row.action}
                onClick={onSelect ? () => onSelect(row.action) : undefined}
                className={cn(
                  "border-b border-border/60 transition-colors last:border-b-0",
                  onSelect && "cursor-pointer hover:bg-muted/60",
                  isSelected && "bg-muted/70",
                )}
              >
                <td className="py-2.5 pr-3">
                  <span className="flex items-center gap-2">
                    <span
                      aria-hidden
                      className={cn(
                        "size-1.5 rounded-full",
                        isSelected ? "bg-foreground" : "bg-border",
                      )}
                    />
                    <span
                      className={cn(
                        "font-semibold tracking-tight",
                        isSelected ? "text-foreground" : "text-foreground/85",
                      )}
                    >
                      {row.action}
                    </span>
                  </span>
                </td>
                <td className="py-2.5 pr-3 text-muted-foreground">{row.containment}</td>
                <td className="py-2.5 pr-3 text-muted-foreground">{row.disruption}</td>
                <td className="py-2.5 pr-3 text-muted-foreground">{row.speed}</td>
                <td className="py-2.5 pr-3 text-muted-foreground">{row.cost}</td>
                <td className="py-2.5 pr-3 text-muted-foreground">{row.exposure}</td>
                <td className="py-2.5 pr-3 text-right tabular-nums">
                  <span className="inline-flex items-center justify-end gap-2">
                    <span className="h-1 w-14 overflow-hidden rounded-full bg-muted">
                      <span
                        className="block h-full rounded-full bg-foreground/70"
                        style={{ width: `${row.normalized}%` }}
                      />
                    </span>
                    <span className="w-8 text-[12px] font-medium">{row.normalized}</span>
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
