import { ApiError, apiFetch, getAuthToken, probeBackend, setAuthToken } from "@/lib/api";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type Role = "ADMIN" | "SOC_ANALYST" | "VIEWER";
export type ApiMode = "loading" | "backend" | "local";

export interface SessionUser {
  id: string;
  name: string;
  email: string;
  role: Role;
}

interface AuthContextValue {
  isLoading: boolean;
  isAuthenticated: boolean;
  user: SessionUser | null;
  mode: ApiMode;
  signIn: (email: string, password: string) => Promise<void>;
  register: (name: string, email: string, password: string, role: Role) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/* ------------------------------------------------------------------ *
 * Local (no-backend) demo accounts
 * ------------------------------------------------------------------ */

const ACCOUNTS_KEY = "cybersentinel.accounts";
const SESSION_KEY = "cybersentinel.session";

interface StoredAccount {
  id: string;
  name: string;
  email: string;
  role: Role;
  digest: string;
}

/** DEMO ONLY — non-reversible digest so the local fallback never stores a password. */
async function digest(value: string): Promise<string> {
  try {
    const bytes = new TextEncoder().encode(`cybersentinel::${value}`);
    const buffer = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(buffer))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    let hash = 5381;
    for (let i = 0; i < value.length; i++) hash = (hash * 33) ^ value.charCodeAt(i);
    return `fallback-${(hash >>> 0).toString(16)}`;
  }
}

const SEED_ACCOUNTS: Array<Omit<StoredAccount, "digest"> & { password: string }> = [
  { id: "usr-admin", name: "Avery Nakamura", email: "admin@cybersentinel.dev", role: "ADMIN", password: "sentinel" },
  { id: "usr-analyst", name: "Robin Okafor", email: "analyst@cybersentinel.dev", role: "SOC_ANALYST", password: "sentinel" },
  { id: "usr-viewer", name: "Sam Delacroix", email: "viewer@cybersentinel.dev", role: "VIEWER", password: "sentinel" },
];

async function readAccounts(): Promise<StoredAccount[]> {
  try {
    const raw = window.localStorage.getItem(ACCOUNTS_KEY);
    if (raw) return JSON.parse(raw) as StoredAccount[];
  } catch {
    /* fall through to seeding */
  }
  const seeded: StoredAccount[] = [];
  for (const account of SEED_ACCOUNTS) {
    const { password, ...rest } = account;
    seeded.push({ ...rest, digest: await digest(password) });
  }
  try {
    window.localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(seeded));
  } catch {
    /* ignore */
  }
  return seeded;
}

async function writeAccounts(accounts: StoredAccount[]): Promise<void> {
  try {
    window.localStorage.setItem(ACCOUNTS_KEY, JSON.stringify(accounts));
  } catch {
    /* ignore */
  }
}

function readLocalSession(): SessionUser | null {
  try {
    const raw = window.localStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as SessionUser) : null;
  } catch {
    return null;
  }
}

function writeLocalSession(user: SessionUser | null): void {
  try {
    if (user) window.localStorage.setItem(SESSION_KEY, JSON.stringify(user));
    else window.localStorage.removeItem(SESSION_KEY);
  } catch {
    /* ignore */
  }
}

/* ------------------------------------------------------------------ *
 * Provider
 * ------------------------------------------------------------------ */

export function AuthProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<ApiMode>("loading");
  const [user, setUser] = useState<SessionUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function boot() {
      const backendUp = await probeBackend();
      if (cancelled) return;

      if (backendUp) {
        setMode("backend");
        const token = getAuthToken();
        if (!token) {
          setIsLoading(false);
          return;
        }
        try {
          const me = await apiFetch<{ user: SessionUser }>("/api/auth/me");
          if (!cancelled) setUser(me.user);
        } catch {
          setAuthToken(null);
        }
        if (!cancelled) setIsLoading(false);
        return;
      }

      setMode("local");
      await readAccounts();
      if (cancelled) return;
      setUser(readLocalSession());
      setIsLoading(false);
    }

    void boot();
    return () => {
      cancelled = true;
    };
  }, []);

  const signIn = useCallback(
    async (email: string, password: string) => {
      const normalized = email.trim().toLowerCase();
      if (!normalized || !password) throw new Error("Enter your email and password.");

      if (mode === "backend") {
        const response = await apiFetch<{ token: string; user: SessionUser }>(
          "/api/auth/login",
          { method: "POST", body: JSON.stringify({ email: normalized, password }) },
        );
        setAuthToken(response.token);
        setUser(response.user);
        return;
      }

      const accounts = await readAccounts();
      const candidate = accounts.find((account) => account.email === normalized);
      if (!candidate) {
        throw new Error(
          "No local account for that email. Use one of the demo credentials below, or create an account.",
        );
      }
      const actual = await digest(password);
      if (candidate.digest !== actual) throw new Error("Invalid email or password.");
      const session: SessionUser = {
        id: candidate.id,
        name: candidate.name,
        email: candidate.email,
        role: candidate.role,
      };
      writeLocalSession(session);
      setUser(session);
    },
    [mode],
  );

  const register = useCallback(
    async (name: string, email: string, password: string, role: Role) => {
      const normalized = email.trim().toLowerCase();
      if (name.trim().length < 2) throw new Error("Enter your full name.");
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
        throw new Error("Enter a valid email address.");
      }
      if (password.length < 6) throw new Error("Password must be at least 6 characters.");

      if (mode === "backend") {
        const response = await apiFetch<{ token: string; user: SessionUser }>(
          "/api/auth/register",
          { method: "POST", body: JSON.stringify({ name: name.trim(), email: normalized, password, role }) },
        );
        setAuthToken(response.token);
        setUser(response.user);
        return;
      }

      const accounts = await readAccounts();
      if (accounts.some((account) => account.email === normalized)) {
        throw new Error("An account with that email already exists.");
      }
      const created: StoredAccount = {
        id: `usr-${Date.now().toString(36)}`,
        name: name.trim(),
        email: normalized,
        role,
        digest: await digest(password),
      };
      accounts.push(created);
      await writeAccounts(accounts);
      const session: SessionUser = {
        id: created.id,
        name: created.name,
        email: created.email,
        role: created.role,
      };
      writeLocalSession(session);
      setUser(session);
    },
    [mode],
  );

  const signOut = useCallback(async () => {
    if (mode === "backend") setAuthToken(null);
    writeLocalSession(null);
    setUser(null);
  }, [mode]);

  const value = useMemo<AuthContextValue>(
    () => ({
      isLoading: mode === "loading" || isLoading,
      isAuthenticated: user !== null,
      user,
      mode,
      signIn,
      register,
      signOut,
    }),
    [mode, isLoading, user, signIn, register, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}

export { ApiError };
