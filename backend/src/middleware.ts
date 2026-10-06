import { env } from "./env";
import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { ZodError, type ZodTypeAny, type z } from "zod";
import type { ROLES } from "./models";

export type Role = (typeof ROLES)[number];

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: Role;
}

declare module "express-serve-static-core" {
  interface Request {
    user?: AuthUser;
  }
}

export function signToken(user: AuthUser): string {
  return jwt.sign(user, env.JWT_SECRET, { expiresIn: env.JWT_EXPIRES_IN } as jwt.SignOptions);
}

/** Bearer-token guard. Required on every route that is not explicitly public. */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }
  try {
    const payload = jwt.verify(header.slice(7), env.JWT_SECRET) as AuthUser;
    req.user = payload;
    next();
  } catch {
    res.status(401).json({ error: "Session expired or token invalid. Sign in again." });
  }
}

/** Role guard — ADMIN can do everything, analysts investigate, viewers read. */
export function requireRole(...roles: Role[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (req.user.role === "ADMIN" || roles.includes(req.user.role)) {
      next();
      return;
    }
    res.status(403).json({
      error: `Role ${req.user.role} is not permitted to perform this action.`,
    });
  };
}

/** Zod body validation — the single entry point for all request payloads. */
export function validate<T extends ZodTypeAny>(schema: T) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: "Validation failed.",
        details: (parsed.error as ZodError).issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      });
      return;
    }
    req.body = parsed.data;
    next();
  };
}

export function parsed<T extends ZodTypeAny>(schema: T, value: unknown): z.infer<T> {
  return schema.parse(value) as z.infer<T>;
}

export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Centralised error handler — consistent JSON, never leaks internals. */
export function errorHandler(
  error: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (error instanceof HttpError) {
    res.status(error.status).json({ error: error.message });
    return;
  }
  if (error instanceof ZodError) {
    res.status(400).json({
      error: "Validation failed.",
      details: error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    });
    return;
  }
  console.error("[api] unhandled error:", error instanceof Error ? error.message : error);
  res.status(500).json({ error: "Unexpected server error. Please try again." });
}

export function notFound(_req: Request, res: Response): void {
  res.status(404).json({ error: "Endpoint not found." });
}
