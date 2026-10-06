import { analyzeSecurityEvent } from "./services/decisionService";
import { generateEvent, type SimServer } from "../../shared";

/**
 * Live attack simulation control (spec §12, §42).
 *
 * Generates synthetic traffic on an interval and runs it through the real
 * routing engine. Every event is fabricated — nothing is scanned, probed or
 * contacted.
 */

export interface SimulationStatus {
  running: boolean;
  startedAt: number | null;
  eventsGenerated: number;
  contained: number;
  escalations: number;
  dismissed: number;
  speedMs: number;
}

let handle: NodeJS.Timeout | null = null;
const status: SimulationStatus = {
  running: false,
  startedAt: null,
  eventsGenerated: 0,
  contained: 0,
  escalations: 0,
  dismissed: 0,
  speedMs: 3000,
};

function nextEvent(fleet: SimServer[], actor: string) {
  return generateEvent({ fleet, timestamp: Date.now(), seed: Date.now() });
}

export async function startSimulation(fleet: SimServer[], speedMs = 3000): Promise<SimulationStatus> {
  if (handle) return { ...status };
  status.running = true;
  status.startedAt = Date.now();
  status.speedMs = speedMs;

  handle = setInterval(() => {
    void (async () => {
      try {
        const result = await analyzeSecurityEvent({
          generatedEvent: nextEvent(fleet, "simulation"),
          actor: "simulation",
        });
        status.eventsGenerated += 1;
        if (result.route === "CONTAIN") status.contained += 1;
        else if (result.route === "GRAY") status.escalations += 1;
        else status.dismissed += 1;
      } catch (error) {
        console.warn(
          "[simulation] tick failed:",
          error instanceof Error ? error.message : error,
        );
      }
    })();
  }, Math.max(750, speedMs));

  return { ...status };
}

export function stopSimulation(): SimulationStatus {
  if (handle) {
    clearInterval(handle);
    handle = null;
  }
  status.running = false;
  return { ...status };
}

export function simulationStatus(): SimulationStatus {
  return { ...status };
}
