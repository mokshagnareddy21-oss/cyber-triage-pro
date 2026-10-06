import { Server } from "../models";
import type { ServerStatus } from "../../../shared/types";

/**
 * Simulated containment (spec §35).
 *
 * These functions ONLY mutate the `status` field of a document in this
 * application's own database. They never execute an operating-system command,
 * never open a firewall, and never reach production infrastructure.
 *
 * Every response that carries one of these actions is labelled
 * "SIMULATED ACTION · DEMO ENVIRONMENT" in the UI.
 */

async function setStatus(serverId: string, status: ServerStatus) {
  const server = await Server.findOneAndUpdate(
    { serverId },
    { status, lastEventAt: new Date() },
    { new: true },
  );
  if (!server) throw new Error(`Unknown server: ${serverId}`);
  return server;
}

export function isolateHost(serverId: string) {
  return setStatus(serverId, "ISOLATED");
}

export function quarantineHost(serverId: string) {
  return setStatus(serverId, "INVESTIGATING");
}

export function throttleConnection(serverId: string) {
  return setStatus(serverId, "THROTTLED");
}

export function allowConnection(serverId: string) {
  return setStatus(serverId, "MONITORING");
}

export function markInvestigating(serverId: string) {
  return setStatus(serverId, "INVESTIGATING");
}

/** Dispatch the simulated action chosen by the Decision Engine. */
export async function applySimulatedAction(
  action: string,
  serverId: string,
): Promise<ServerStatus> {
  switch (action) {
    case "ISOLATE":
      await isolateHost(serverId);
      return "ISOLATED";
    case "QUARANTINE":
      await quarantineHost(serverId);
      return "INVESTIGATING";
    case "THROTTLE":
      await throttleConnection(serverId);
      return "THROTTLED";
    case "ALLOW":
      await allowConnection(serverId);
      return "MONITORING";
    case "BLOCK":
      await throttleConnection(serverId);
      return "THROTTLED";
    default:
      await markInvestigating(serverId);
      return "INVESTIGATING";
  }
}
