// src/Login.tsx
import React, { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function Login() {
  const { login, user } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();
  const location = useLocation() as any;

  const from = location.state?.from || "/";

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(email, password);
      // If we know the user is creator later, we can redirect to their dashboard
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  if (user) {
    // already logged in
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="border rounded-2xl p-6 max-w-md w-full text-center">
          <p className="mb-4">You are already logged in as @{user.username}.</p>
          <button
            onClick={() => navigate("/")}
            className="px-4 py-2 rounded-xl bg-brand-600 text-white font-semibold"
          >
            Go to home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white flex items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md border rounded-2xl p-6 space-y-4"
      >
        <h1 className="text-2xl font-extrabold">Log in</h1>
        <p className="text-sm text-gray-600">
          Log in to access your subscriptions or creator dashboard.
        </p>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Email
          </label>
          <input
            type="email"
            className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Password
          </label>
          <input
            type="password"
            className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>

        {error && (
          <p className="text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="w-full rounded-2xl px-4 py-2.5 bg-brand-600 text-white font-semibold hover:bg-brand-700 disabled:bg-gray-300"
        >
          {submitting ? "Logging in…" : "Log in"}
        </button>

        <p className="text-xs text-gray-600 text-center">
          Don&apos;t have an account?{" "}
          <Link to="/signup" className="text-brand-700 font-semibold">
            Sign up
          </Link>
        </p>
      </form>
    </div>
  );
}
