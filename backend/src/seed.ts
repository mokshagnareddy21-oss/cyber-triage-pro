import { env } from "./env";
import { SecurityEvent, Server, User } from "./models";
import { analyzeSecurityEvent } from "./services/decisionService";
import { buildFleet, resetEventCounter, type SimServer } from "../../shared";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";

/**
 * Seed script (spec §36).
 *
 * Populates 50 synthetic servers, three demo accounts and a realistic history
 * of benign / suspicious / malicious events so the dashboard looks alive the
 * moment someone signs in. Everything is fabricated.
 *
 *   npm run seed
 */

const DEMO_PASSWORD = "sentinel";

const DEMO_USERS = [
  { name: "Avery Nakamura", email: "admin@cybersentinel.dev", role: "ADMIN" as const },
  { name: "Robin Okafor", email: "analyst@cybersentinel.dev", role: "SOC_ANALYST" as const },
  { name: "Sam Delacroix", email: "viewer@cybersentinel.dev", role: "VIEWER" as const },
];

const HISTORY_EVENTS = 40;

async function seedServers(): Promise<SimServer[]> {
  const fleet = buildFleet(50);
  for (const server of fleet) {
    await Server.updateOne(
      { serverId: server.serverId },
      {
        $set: {
          hostname: server.hostname,
          region: server.region,
          os: server.os,
          status: server.status,
          threatScore: server.threatScore,
          criticality: server.criticality,
          cpu: server.cpu,
          network: server.network,
        },
        $setOnInsert: { lastEventAt: null },
      },
      { upsert: true },
    );
  }
  return fleet;
}

async function seedUsers(): Promise<void> {
  for (const account of DEMO_USERS) {
    const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 12);
    await User.updateOne(
      { email: account.email },
      { $set: { name: account.name, role: account.role, passwordHash } },
      { upsert: true },
    );
  }
}

async function seedHistory(fleet: SimServer[]): Promise<void> {
  resetEventCounter(0);
  const existing = await SecurityEvent.estimatedDocumentCount();
  if (existing > 0) {
    console.log(`[seed] ${existing} events already present — skipping history generation.`);
    return;
  }

  const now = Date.now();
  for (let index = HISTORY_EVENTS; index >= 1; index--) {
    const timestamp = now - index * 4 * 60_000 - index * 7_000;
    const { generateEvent } = await import("../../shared");
    const event = generateEvent({ fleet, timestamp, seed: timestamp + index });
    await analyzeSecurityEvent({ scenarioEvent: event, actor: "seed" });
  }
  console.log(`[seed] generated ${HISTORY_EVENTS} historical events.`);
}

async function main() {
  if (!env.MONGODB_URI) {
    console.error("[seed] MONGODB_URI is not set. Configure backend/.env first.");
    process.exit(1);
  }

  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
  const fleet = await seedServers();
  await seedUsers();
  await seedHistory(fleet);

  console.log("[seed] done.");
  console.log("[seed] demo accounts (password: sentinel):");
  for (const account of DEMO_USERS) console.log(`       ${account.email} → ${account.role}`);

  await mongoose.disconnect();
}

void main().catch((error) => {
  console.error("[seed] failed:", error instanceof Error ? error.message : error);
  process.exit(1);
});
