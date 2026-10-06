import { env } from "./env";
import { errorHandler, notFound } from "./middleware";
import { router } from "./routes";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

/**
 * Express application (spec §31, §47).
 *
 * Security posture: helmet headers, CORS restricted to the deployed frontend,
 * a global rate limit plus a stricter one on authentication, JSON body capping,
 * Zod validation on every mutating route and a single error handler that never
 * leaks internals or API keys.
 */
export function createApp() {
  const app = express();

  app.set("trust proxy", 1);
  app.disable("x-powered-by");

  app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
  app.use(
    cors({
      origin: env.CLIENT_URL.split(",").map((value) => value.trim()).filter(Boolean),
      credentials: false,
    }),
  );
  app.use(express.json({ limit: "256kb" }));

  app.use(
    "/api",
    rateLimit({
      windowMs: 60_000,
      limit: 600,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      message: { error: "Too many requests. Please slow down." },
    }),
  );

  app.use(
    "/api/auth",
    rateLimit({
      windowMs: 15 * 60_000,
      limit: 40,
      standardHeaders: "draft-7",
      legacyHeaders: false,
      message: { error: "Too many authentication attempts. Try again shortly." },
    }),
  );

  app.use("/api", router);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
