import { Wordmark } from "@/components/Mark";
import { Button } from "@/components/ui/button";
import { motion } from "framer-motion";
import { useNavigate } from "react-router";

export default function NotFound() {
  const navigate = useNavigate();

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="flex min-h-screen flex-col bg-background"
    >
      <header className="border-b">
        <div className="mx-auto flex h-14 max-w-6xl items-center px-5">
          <button
            type="button"
            onClick={() => navigate("/")}
            className="cursor-pointer transition-opacity hover:opacity-70"
          >
            <Wordmark />
          </button>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col justify-center px-5 py-16">
        <span className="text-[11px] font-semibold tracking-[0.24em] text-muted-foreground uppercase">
          Route not found
        </span>
        <h1 className="mt-4 text-6xl font-semibold tracking-[-0.03em] tabular-nums">404</h1>
        <p className="mt-3 max-w-md text-[14.5px] leading-relaxed text-muted-foreground">
          This page does not exist. The decision console lives at{" "}
          <span className="font-mono text-foreground">/app</span>.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <Button onClick={() => navigate("/")}>Back to overview</Button>
          <Button variant="outline" onClick={() => navigate("/app")}>
            Open SOC console
          </Button>
        </div>
      </main>
    </motion.div>
  );
}
