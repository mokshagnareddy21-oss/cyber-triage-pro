import { Mark } from "@/components/Mark";
import { Chip } from "@/components/chips";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth, type Role } from "@/hooks/use-auth";
import { ArrowRight, Loader2 } from "lucide-react";
import { Suspense, useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";

interface AuthProps {
  redirectAfterAuth?: string;
}

const DEMO_ACCOUNTS: Array<{ email: string; role: Role; note: string }> = [
  { email: "admin@cybersentinel.dev", role: "ADMIN", note: "full access" },
  { email: "analyst@cybersentinel.dev", role: "SOC_ANALYST", note: "triage + review" },
  { email: "viewer@cybersentinel.dev", role: "VIEWER", note: "read-only" },
];

function resolveRedirectAfterAuth(returnTo: string | null, fallback = "/app") {
  if (returnTo?.startsWith("/") && !returnTo.startsWith("//")) return returnTo;
  return fallback;
}

function Auth({ redirectAfterAuth }: AuthProps = {}) {
  const { isLoading: authLoading, isAuthenticated, signIn, register, mode } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirect = resolveRedirectAfterAuth(searchParams.get("returnTo"), redirectAfterAuth);

  const [tab, setTab] = useState<"signin" | "register">("signin");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && isAuthenticated) navigate(redirect);
  }, [authLoading, isAuthenticated, navigate, redirect]);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsSubmitting(true);
    setError(null);
    const data = new FormData(event.currentTarget);
    try {
      if (tab === "signin") {
        await signIn(String(data.get("email") ?? ""), String(data.get("password") ?? ""));
      } else {
        const role = String(data.get("role") ?? "SOC_ANALYST") as Role;
        await register(
          String(data.get("name") ?? ""),
          String(data.get("email") ?? ""),
          String(data.get("password") ?? ""),
          role,
        );
      }
      navigate(redirect);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Something went wrong. Try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const useDemo = (email: string) => {
    setTab("signin");
    setError(null);
    const form = document.getElementById("auth-form") as HTMLFormElement | null;
    if (form) {
      const emailInput = form.elements.namedItem("email") as HTMLInputElement | null;
      const passwordInput = form.elements.namedItem("password") as HTMLInputElement | null;
      if (emailInput) emailInput.value = email;
      if (passwordInput) passwordInput.value = "sentinel";
    }
  };

  return (
    <div className="min-h-screen bg-background lg:grid lg:grid-cols-[1fr_1.05fr]">
      {/* ---- Left: product statement ---- */}
      <div className="flex flex-col justify-between border-b px-6 py-10 lg:border-r lg:border-b-0 lg:px-12 lg:py-12">
        <button
          type="button"
          onClick={() => navigate("/")}
          className="flex w-fit cursor-pointer items-center gap-2.5 transition-opacity hover:opacity-70"
        >
          <Mark className="size-5" />
          <span className="text-[13px] font-semibold tracking-[0.16em] uppercase">
            CyberSentinel
          </span>
          <span className="text-[11px] tracking-[0.12em] text-muted-foreground tabular-nums">
            v2.0
          </span>
        </button>

        <div className="py-12">
          <span className="text-[11px] font-semibold tracking-[0.24em] text-muted-foreground uppercase">
            The Probabilistic SOC Copilot
          </span>
          <h1 className="mt-5 max-w-md text-3xl leading-tight font-semibold tracking-tight">
            Sign in to the decision console.
          </h1>
          <p className="mt-4 max-w-md text-[14px] leading-relaxed text-muted-foreground">
            Ingest events, watch the fast model triage them against two probability thresholds,
            and review every containment decision with its full reasoning chain.
          </p>

          <ol className="mt-8 flex max-w-md flex-col gap-px border bg-border">
            {[
              ["Fast triage", "probability + classification + blast radius"],
              ["Threshold", "0.95 contains · 0.40 dismisses"],
              ["Escalation", "only the gray zone reaches deep forensics"],
            ].map(([title, detail], index) => (
              <li key={title} className="flex gap-3 bg-background px-4 py-3">
                <span className="font-mono text-[11px] text-muted-foreground tabular-nums">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span>
                  <span className="block text-[13px] font-medium">{title}</span>
                  <span className="block text-[12px] text-muted-foreground">{detail}</span>
                </span>
              </li>
            ))}
          </ol>
        </div>

        <p className="max-w-md text-[11.5px] leading-relaxed text-muted-foreground">
          Authenticated requests carry a signed bearer token. Model keys stay on the server — the
          browser never sees them.
        </p>
      </div>

      {/* ---- Right: form ---- */}
      <div className="flex items-center justify-center px-5 py-12">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center justify-between gap-3">
            <div className="flex gap-1 rounded-md border p-0.5">
              {(["signin", "register"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => {
                    setTab(value);
                    setError(null);
                  }}
                  className={`cursor-pointer rounded px-3 py-1.5 text-[12.5px] transition-colors ${
                    tab === value
                      ? "bg-foreground font-medium text-background"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {value === "signin" ? "Sign in" : "Create account"}
                </button>
              ))}
            </div>
            <Chip tone={mode === "backend" ? "info" : "warning"}>
              {mode === "backend" ? "API CONNECTED" : "LOCAL DEMO"}
            </Chip>
          </div>

          <Card className="border shadow-none">
            <CardHeader className="pb-4">
              <h2 className="text-lg font-semibold tracking-tight">
                {tab === "signin" ? "Welcome back" : "Create your analyst account"}
              </h2>
              <p className="text-[13px] text-muted-foreground">
                {tab === "signin"
                  ? "Use a demo credential below, or your own account."
                  : "Accounts are created with SOC_ANALYST access by default."}
              </p>
            </CardHeader>

            <CardContent>
              <form id="auth-form" onSubmit={handleSubmit} className="flex flex-col gap-4">
                {tab === "register" && (
                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="name" className="text-[11px] tracking-[0.1em] uppercase">
                      Full name
                    </Label>
                    <Input id="name" name="name" placeholder="Robin Okafor" required minLength={2} />
                  </div>
                )}

                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="email" className="text-[11px] tracking-[0.1em] uppercase">
                    Work email
                  </Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    placeholder="analyst@cybersentinel.dev"
                    required
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <Label htmlFor="password" className="text-[11px] tracking-[0.1em] uppercase">
                    Password
                  </Label>
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    autoComplete={tab === "signin" ? "current-password" : "new-password"}
                    placeholder="••••••••"
                    required
                    minLength={6}
                  />
                </div>

                {tab === "register" && (
                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="role" className="text-[11px] tracking-[0.1em] uppercase">
                      Role
                    </Label>
                    <select
                      id="role"
                      name="role"
                      defaultValue="SOC_ANALYST"
                      className="h-9 w-full cursor-pointer rounded-md border border-input bg-background px-3 text-[13px] outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]"
                    >
                      <option value="SOC_ANALYST">SOC_ANALYST — triage and review</option>
                      <option value="VIEWER">VIEWER — read-only</option>
                    </select>
                  </div>
                )}

                {error && (
                  <p className="rounded-md border border-[var(--signal-critical-line)] bg-[var(--signal-critical-bg)] px-3 py-2 text-[12.5px] text-[var(--signal-critical)]">
                    {error}
                  </p>
                )}

                <Button type="submit" className="w-full gap-2" disabled={isSubmitting}>
                  {isSubmitting ? (
                    <>
                      <Loader2 className="size-4 animate-spin" />
                      Working…
                    </>
                  ) : (
                    <>
                      {tab === "signin" ? "Sign in" : "Create account"}
                      <ArrowRight className="size-4" />
                    </>
                  )}
                </Button>
              </form>
            </CardContent>
          </Card>

          <div className="mt-6 rounded-lg border">
            <div className="flex items-center justify-between border-b px-4 py-2.5">
              <span className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
                Demo credentials
              </span>
              <span className="text-[10.5px] text-muted-foreground">password: sentinel</span>
            </div>
            <ul className="divide-y divide-border/60">
              {DEMO_ACCOUNTS.map((account) => (
                <li key={account.email} className="flex items-center gap-3 px-4 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[12px]">{account.email}</div>
                    <div className="text-[11px] text-muted-foreground">{account.note}</div>
                  </div>
                  <Chip tone="neutral">{account.role}</Chip>
                  <Button size="sm" variant="outline" onClick={() => useDemo(account.email)}>
                    Use
                  </Button>
                </li>
              ))}
            </ul>
          </div>

          <p className="mt-4 text-center text-[11.5px] text-muted-foreground">
            Demo use only — documented in the README, never for production.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function AuthPage(props: AuthProps) {
  return (
    <Suspense>
      <Auth {...props} />
    </Suspense>
  );
}
