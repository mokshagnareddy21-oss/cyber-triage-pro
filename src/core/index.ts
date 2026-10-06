/**
 * Frontend entry point into the shared decision core.
 *
 * The engine itself lives at `/shared` so the Express backend can import the
 * exact same code. Nothing in `src/` is allowed to re-implement routing,
 * scoring or fixtures — if the queue and the API ever disagree about a
 * decision, the bug is in this barrel.
 */
export * from "../../shared/types";
export * from "../../shared/thresholds";
export * from "../../shared/decision";
export * from "../../shared/fixtures";
export * from "../../shared/telemetry";
export * from "../../shared/triage";
export * from "../../shared/rng";
