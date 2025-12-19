import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../AuthContext";

export default function Signup() {
  const { signup } = useAuth();
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  // email verify state
  const [emailSent, setEmailSent] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);
  const [codeSent, setCodeSent] = useState<string>("");
  const [codeInput, setCodeInput] = useState("");
  const [sendingCode, setSendingCode] = useState(false);
  const [verifyingCode, setVerifyingCode] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const emailOk = /.+@.+\..+/.test(email);
  const usernameOk = /^[a-z0-9_]+$/.test(username.trim());
  const passwordOk = password.trim().length >= 6;

  const canSubmit =
    username.trim().length >= 3 &&
    usernameOk &&
    passwordOk &&
    emailOk &&
    emailVerified &&
    !submitting;

  async function handleSendCode() {
    if (!emailOk) return;
    setSendingCode(true);
    setError(null);
    setEmailVerified(false);

    // TODO: replace with real backend call
    await new Promise((r) => setTimeout(r, 600));
    setCodeSent("123456");
    setEmailSent(true);
    setSendingCode(false);
  }

  async function handleVerifyCode() {
    if (!emailSent || !codeInput) return;
    setVerifyingCode(true);
    setError(null);

    await new Promise((r) => setTimeout(r, 600));
    if (codeInput === codeSent) {
      setEmailVerified(true);
      setError(null);
    } else {
      setEmailVerified(false);
      setError("Incorrect verification code. Please try again.");
    }
    setVerifyingCode(false);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setError(null);

    try {
      // 🔹 Call real backend signup so we can enforce unique email/username
      const res = await fetch("http://localhost:4000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          username: username.trim().toLowerCase(),
          password: password.trim(),
        }),
      });

      if (!res.ok) {
        let msg = "Signup failed";
        try {
          const data = await res.json();
          if (data.error) msg = data.error;
        } catch {
          // ignore JSON parse errors
        }
        setError(msg); // 🔴 shows in red box below
        setSubmitting(false);
        return;
      }

      const data = await res.json(); // { id, email, username, role }

      // 🔹 Keep your existing AuthContext behaviour
      await signup(data.email, password, data.username);

      navigate("/");
    } catch (err: any) {
      setError(err.message || "Signup failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md border rounded-2xl bg-white p-6 space-y-4 shadow-sm"
      >
        <h1 className="text-2xl font-extrabold">Create your Faniko account</h1>
        <p className="text-sm text-gray-600">
          Sign up as a fan to follow creators and unlock exclusive content. You
          can always apply to become a creator later.
        </p>

        {/* Username */}
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Username
          </label>
          <input
            className="mt-1 w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-400"
            placeholder="e.g. mikhail_01"
            value={username}
            onChange={(e) => setUsername(e.target.value.toLowerCase())}
            required
          />
          <p className="mt-1 text-[11px] text-gray-500">
            3+ characters, letters/numbers/underscores only.
          </p>
          {username.length > 0 && !usernameOk && (
            <p className="mt-1 text-[11px] text-red-600">
              Username can only contain lowercase letters, numbers, and
              underscores.
            </p>
          )}
        </div>

        {/* Email + verify */}
        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700">
            Email
          </label>
          <div className="flex gap-2">
            <input
              type="email"
              className="mt-1 w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-400"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setEmailVerified(false);
                setEmailSent(false);
              }}
              required
            />
            <button
              type="button"
              disabled={!emailOk || sendingCode}
              onClick={handleSendCode}
              className="mt-1 whitespace-nowrap rounded-xl border border-gray-300 px-3 py-2 text-xs font-semibold hover:bg-gray-50 disabled:bg-gray-100 disabled:text-gray-400"
            >
              {sendingCode ? "Sending..." : emailSent ? "Resend" : "Send code"}
            </button>
          </div>
          {!emailOk && email.length > 0 && (
            <p className="text-[11px] text-red-600">
              Please enter a valid email.
            </p>
          )}
          {emailSent && (
            <div className="space-y-1">
              <div className="flex gap-2">
                <input
                  className="mt-1 w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-400"
                  placeholder="Enter 6-digit code"
                  value={codeInput}
                  onChange={(e) => setCodeInput(e.target.value)}
                />
                <button
                  type="button"
                  disabled={verifyingCode || !codeInput}
                  onClick={handleVerifyCode}
                  className="mt-1 whitespace-nowrap rounded-xl bg-gray-900 text-white px-3 py-2 text-xs font-semibold hover:bg-gray-800 disabled:bg-gray-400"
                >
                  {verifyingCode ? "Checking…" : "Verify"}
                </button>
              </div>
              <p className="text-[11px] text-gray-500">
                We sent a code to your email (demo: use{" "}
                <span className="font-mono">123456</span>).
              </p>
              {emailVerified && (
                <p className="text-[11px] text-green-600">
                  Email verified successfully.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Password */}
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Password
          </label>
          <input
            type="password"
            className="mt-1 w-full rounded-xl border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-400"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <p className="mt-1 text-[11px] text-gray-500">
            At least 6 characters.
          </p>
        </div>

        {error && (
          <p className="text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="w-full rounded-2xl px-4 py-2.5 bg-brand-600 text-white text-sm font-semibold hover:bg-brand-700 disabled:bg-gray-300"
        >
          {submitting ? "Creating account…" : "Sign up"}
        </button>

        <p className="text-xs text-gray-600 text-center">
          Already have an account?{" "}
          <Link to="/login" className="text-brand-700 font-semibold">
            Log in
          </Link>
        </p>
      </form>
    </div>
  );
}

