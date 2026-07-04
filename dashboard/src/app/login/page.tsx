"use client";

import { Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Ghost } from "lucide-react";

function LoginForm() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });

      if (res.ok) {
        const redirect = searchParams.get("redirect") || "/";
        router.push(redirect);
      } else {
        setError("Invalid password");
      }
    } catch {
      setError("Connection error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="w-full max-w-sm p-8 space-y-6">
        <div className="flex flex-col items-center space-y-2">
          <Ghost size={48} strokeWidth={1.75} style={{ color: "var(--accent)" }} aria-hidden="true" />
          <h1 className="text-xl font-semibold text-gray-100">Agathion Node</h1>
          <p className="text-sm text-gray-400">Your node&apos;s familiar — enter your password</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg text-gray-100 placeholder-gray-500 focus:outline-none focus:border-orange-500"
            autoFocus
          />

          {error && <p className="text-sm text-red-400">{error}</p>}

          <button
            type="submit"
            disabled={loading || !password}
            className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-lg font-medium transition-colors"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <details className="text-sm text-gray-400">
          <summary className="cursor-pointer text-gray-500 hover:text-gray-300 transition-colors select-none">
            Forgot password?
          </summary>
          <div className="mt-3 space-y-2 rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <p>
              There is no web reset — that would let anyone who can reach this
              page bypass the password. Recovery requires access to the node
              itself. On the node (over SSH or locally), run as root:
            </p>
            <pre className="overflow-x-auto rounded bg-gray-950 px-3 py-2 text-xs text-gray-300">
              <code>sudo scripts/agathion-reset-password.sh</code>
            </pre>
            <p>
              It sets a fresh password, prints it, and restarts the dashboard.
              Then sign in here with the new password.
            </p>
          </div>
        </details>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
