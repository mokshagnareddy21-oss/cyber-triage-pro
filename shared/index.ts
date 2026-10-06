/**
 * Shared decision core — one implementation of triage, routing, scoring and
 * fixtures, imported by both the Vite frontend (via `src/core`) and the Express
 * backend (via `shared`).
 */
export * from "./types";
export * from "./thresholds";
export * from "./decision";
export * from "./fixtures";
export * from "./telemetry";
export * from "./triage";
export * from "./rng";
