import { env, warnAboutInsecureConfig } from "./env";
import { createApp } from "./app";
import mongoose from "mongoose";

async function main() {
  warnAboutInsecureConfig();

  if (!env.MONGODB_URI) {
    console.error(
      "[startup] MONGODB_URI is not set. Copy backend/env.example to backend/.env and add your Atlas connection string.",
    );
    process.exit(1);
  }

  try {
    await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
    console.log("[startup] connected to MongoDB");
  } catch (error) {
    console.error(
      "[startup] database connection failed:",
      error instanceof Error ? error.message : error,
    );
    process.exit(1);
  }

  const app = createApp();
  app.listen(env.PORT, () => {
    console.log(`[startup] CyberSentinel decision API listening on :${env.PORT}`);
    console.log(`[startup] client origin: ${env.CLIENT_URL}`);
  });
}

void main();
