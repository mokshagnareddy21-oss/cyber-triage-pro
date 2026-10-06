import "dotenv/config";

/**
 * Environment access. Nothing here is ever logged — only whether a key is
 * present, which is what the UI needs to display AI MODE · LIVE vs DEMO FIXTURE.
 *
 * Secrets are read exclusively on the server. The browser bundle never sees
 * JEV_API_KEY, GEMINI_API_KEY, MONGODB_URI or JWT_SECRET.
 */
export const env = {
  PORT: Number(process.env.PORT ?? 4000),
  CLIENT_URL: process.env.CLIENT_URL ?? "http://localhost:5173",
  MONGODB_URI: process.env.MONGODB_URI ?? "",
  JWT_SECRET: process.env.JWT_SECRET ?? "dev-only-change-me-set-JWT_SECRET",
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN ?? "12h",

  JEV_API_KEY: process.env.JEV_API_KEY ?? "",
  JEV_API_URL: process.env.JEV_API_URL ?? "https://api.typesafe.ai/v1/complete",
  JEV_MODEL: process.env.JEV_MODEL ?? "typesafe-jev-1",

  GEMINI_API_KEY: process.env.GEMINI_API_KEY ?? "",
  GEMINI_MODEL: process.env.GEMINI_MODEL ?? "gemini-1.5-pro",

  CONTAIN_THRESHOLD: Number(process.env.CONTAIN_THRESHOLD ?? 0.95),
  DISMISS_THRESHOLD: Number(process.env.DISMISS_THRESHOLD ?? 0.4),
};

export const hasJevKey = () => env.JEV_API_KEY.trim().length > 0;
export const hasGeminiKey = () => env.GEMINI_API_KEY.trim().length > 0;

export function warnAboutInsecureConfig(): void {
  if (env.JWT_SECRET.startsWith("dev-only")) {
    console.warn(
      "[config] JWT_SECRET is still the development default. Set a real secret before deploying.",
    );
  }
  if (!hasJevKey()) console.log("[config] JEV_API_KEY unset → Jev runs in DEMO FIXTURE mode.");
  if (!hasGeminiKey()) {
    console.log("[config] GEMINI_API_KEY unset → Gemini runs in DEMO FIXTURE mode.");
  }
}
