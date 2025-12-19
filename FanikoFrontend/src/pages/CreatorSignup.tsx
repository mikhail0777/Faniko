import { useAuth } from "../AuthContext";
import { useNavigate } from "react-router-dom";
import React, { useState } from "react";

type AccountType = "free" | "subscription";

function classNames(...c: Array<string | false | undefined>) {
  return c.filter(Boolean).join(" ");
}

function PrettyFileInput({
  label,
  onChange,
  required,
}: {
  label: string;
  onChange: (file: File | null) => void;
  required?: boolean;
}) {
  const [name, setName] = useState<string>("");

  return (
    <div className="w-full">
      <label className="block text-sm font-medium text-gray-700">{label}</label>
      <label className="mt-1 inline-flex items-center gap-2 rounded-xl border border-dashed border-gray-300 bg-gray-50 px-4 py-2 cursor-pointer hover:bg-gray-50 w-full max-w-full overflow-hidden">
        <input
          type="file"
          accept="image/*"
          className="sr-only"
          required={required}
          onChange={(e) => {
            const f = e.target.files?.[0] || null;
            setName(f ? f.name : "");
            onChange(f);
          }}
        />
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className="h-5 w-5 text-gray-400"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={1.5}
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M3 16.5V18.75A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 9 12 4.5 7.5 9M12 4.5V15"
          />
        </svg>
        <span className="text-sm font-medium">Choose file</span>
        <span className="text-xs text-gray-500 max-w-[180px] overflow-hidden text-ellipsis whitespace-nowrap">
          {name ? `• ${name}` : "PNG/JPG only"}
        </span>
      </label>
    </div>
  );
}

type MessageType = "success" | "error" | "info" | null;

export default function CreatorSignup() {
  // 🔹 auth + routing
  const { upgradeToCreator, user } = useAuth();
  const navigate = useNavigate();
  const isLoggedIn = !!user;

  // basics
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");

  // email verify (only used when NOT logged in)
  const [emailSent, setEmailSent] = useState(false);
  const [emailVerified, setEmailVerified] = useState(false);
  const [codeSent, setCodeSent] = useState<string>("");
  const [codeInput, setCodeInput] = useState("");

  // password confirmation (used when upgrading as logged-in user)
  const [passwordConfirm, setPasswordConfirm] = useState("");

  // monetization
  const [accountType, setAccountType] = useState<AccountType>("free");
  const [price, setPrice] = useState<string>("9.99");

  // KYC files
  const [idFront, setIdFront] = useState<File | null>(null);
  const [idBack, setIdBack] = useState<File | null>(null);
  const [selfie, setSelfie] = useState<File | null>(null);

  // misc
  const [agree, setAgree] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [messageType, setMessageType] = useState<MessageType>(null);
  const [sendingCode, setSendingCode] = useState(false);
  const [verifyingCode, setVerifyingCode] = useState(false);

  // effective email: from logged-in user if available, otherwise local state
  const effectiveEmail = isLoggedIn ? user?.email || "" : email;
  const emailOk = /.+@.+\..+/.test(effectiveEmail);
  const priceNumber = parseFloat(price) || 0;
  const priceValid = accountType === "free" || priceNumber > 0;

  const canSubmit =
    displayName.trim().length >= 2 &&
    username.trim().length >= 3 &&
    /^[a-z0-9_]+$/.test(username) &&
    priceValid &&
    idFront &&
    idBack &&
    selfie &&
    agree &&
    !submitting &&
    // if NOT logged in, they must verify email
    (!isLoggedIn ? emailVerified : true) &&
    // if logged in, require password confirmation (and we’ll verify it on submit)
    (isLoggedIn ? passwordConfirm.trim().length >= 6 : true);

  const submitError: string | null = (() => {
    if (submitting) return null;

    if (displayName.trim().length < 2) {
      return "Please enter a display name with at least 2 characters.";
    }

    if (username.trim().length < 3) {
      return "Please choose a username with at least 3 characters.";
    }

    if (username && !/^[a-z0-9_]+$/.test(username)) {
      return "Username can only contain lowercase letters, numbers, and underscores.";
    }

    if (!emailOk) {
      return "Please enter a valid email address.";
    }

    if (!isLoggedIn && !emailVerified) {
      return "Please verify your email using the code we sent you.";
    }

    if (isLoggedIn && passwordConfirm.trim().length < 6) {
      return "Please confirm your password (at least 6 characters).";
    }

    if (!priceValid) {
      return "Subscription price must be greater than 0.";
    }

    if (!idFront || !idBack || !selfie) {
      return "Please upload the front and back of your ID and a selfie.";
    }

    if (!agree) {
      return "You must confirm you are 18+ and agree to the terms.";
    }

    return null;
  })();

  // 🔹 Send verification code (fake for now: 123456) – only used when NOT logged in
  async function handleSendCode() {
    if (!emailOk || isLoggedIn) return;
    setSendingCode(true);
    setMessage(null);
    setMessageType(null);
    setEmailVerified(false);

    await new Promise((r) => setTimeout(r, 600));
    setCodeSent("123456");
    setEmailSent(true);
    setSendingCode(false);
  }

  // 🔹 Verify code (also fake: just checks "123456") – only used when NOT logged in
  async function handleVerifyCode() {
    if (isLoggedIn || !emailSent || !codeInput) return;
    setVerifyingCode(true);
    setMessage(null);
    setMessageType(null);

    await new Promise((r) => setTimeout(r, 600));
    const ok = codeInput.trim() === codeSent;
    setEmailVerified(ok);
    setVerifyingCode(false);

    if (ok) {
      setMessage("Email verified successfully ✅");
      setMessageType("success");
    } else {
      setMessage("Incorrect code. Please try again.");
      setMessageType("error");
    }
  }

  // 🔹 Submit application to backend
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    if (!canSubmit || !idFront || !idBack || !selfie) return;

    setSubmitting(true);
    setMessage(null);
    setMessageType(null);

    try {
      const finalEmail = effectiveEmail;

      // ✅ If logged in, verify password against real auth backend first
      if (isLoggedIn) {
        const loginRes = await fetch("http://localhost:4000/api/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: finalEmail.trim().toLowerCase(),
            password: passwordConfirm.trim(),
          }),
        });

        if (!loginRes.ok) {
          let errText = "Incorrect password. Please try again.";
          try {
            const errData = await loginRes.json();
            if (errData.error) errText = errData.error;
          } catch {
            // ignore JSON parse errors
          }
          setMessage(errText);
          setMessageType("error");
          setSubmitting(false);
          return;
        }
      }

      const formData = new FormData();
      formData.append("displayName", displayName);
      formData.append("username", username);
      formData.append("email", finalEmail);
      formData.append("accountType", accountType);
      if (accountType === "subscription") {
        formData.append("price", priceNumber.toString());
      }
      formData.append("idFront", idFront);
      formData.append("idBack", idBack);
      formData.append("selfie", selfie);

      const response = await fetch("http://localhost:4000/api/creators", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let errText = "Failed to submit application.";
        try {
          const errData = await response.json();
          if (errData.error) errText = errData.error;
        } catch {
          // ignore JSON parse errors
        }
        setMessage(errText);
        setMessageType("error");
        throw new Error(errText);
      }

      const data = await response.json();

      // 🔹 figure out the username we should lock this creator to
      const finalUsername =
        username.trim() ||
        user?.username ||
        (finalEmail ? finalEmail.split("@")[0] : "creator");

      // 🔹 upgrade this logged-in account to a CREATOR, same email
      upgradeToCreator({
        username: finalUsername.toLowerCase(),
        email: finalEmail,
      });

      // 🔹 message + redirect
      setMessage(
        `Application submitted! Your creator ID is ${data.creatorId}. Redirecting you to your dashboard…`
      );
      setMessageType("success");

      navigate(`/creator/${finalUsername.toLowerCase()}/dashboard`);
      // (no need to reset; navigation will unmount)
    } catch (err: any) {
      // message already set above if response not ok
      if (!message) {
        setMessage(err.message || "Something went wrong. Please try again.");
        setMessageType("error");
      }
    } finally {
      setSubmitting(false);
    }
  }

  const messageClass =
    messageType === "error"
      ? "text-xs text-red-600"
      : messageType === "success"
      ? "text-xs text-green-600"
      : "text-xs text-gray-600";

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
      <header className="border-b border-gray-100">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/faniko-logo.svg" alt="Faniko" className="h-8 w-8" />
            <span className="font-extrabold text-xl tracking-tight">
              Faniko
            </span>
          </div>
          <nav className="hidden sm:flex items-center gap-6 text-sm">
            <a href="/" className="hover:text-brand-700">
              Home
            </a>
            <a href="#" className="hover:text-brand-700">
              How it works
            </a>
            <a href="/explore" className="hover:text-brand-700">
              Explore creators
            </a>
          </nav>
          {!isLoggedIn && (
            <a
              href="/login"
              className="rounded-full border border-gray-200 px-3 py-1.5 text-xs font-semibold hover:bg-gray-50"
            >
              Log in
            </a>
          )}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-10 grid gap-10 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)] items-start">
        {/* Left: marketing copy */}
        <section className="space-y-4">
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
            Become a creator on{" "}
            <span className="text-brand-700">Faniko</span>
          </h1>
          <p className="mt-2 text-gray-600">
            Keep <strong>90%</strong> of your earnings. Whether free-to-follow
            or subscription, creators earn from
            <strong> tips, pay-per-view posts</strong> (price set per post), and{" "}
            <strong>custom requests</strong>.
          </p>

          <ul className="mt-4 space-y-2 text-sm text-gray-700">
            <li>• No setup fee, no monthly fee.</li>
            <li>• Fans can tip on any post, not just DMs.</li>
            <li>
              • Highest level of protection against piracy, to keep{" "}
              <strong>your</strong> content <strong>yours</strong>.
            </li>
            <li>
              • PPV posts let you lock specific content behind a one-time
              price.
            </li>
          </ul>
        </section>

        {/* Right: form */}
        <form onSubmit={handleSubmit} className="mt-8 grid gap-6">
          {/* Basic info */}
          <section className="grid gap-4 rounded-2xl border p-5">
            <div className="grid sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Display name
                </label>
                <input
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                  placeholder="e.g. Aria Cosplay"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Username
                </label>
                <input
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                  placeholder="ariacos"
                  value={username}
                  onChange={(e) =>
                    setUsername(e.target.value.toLowerCase())
                  }
                  pattern="[a-z0-9_]+"
                  minLength={3}
                  required
                />
                <p className="mt-1 text-xs text-gray-500">
                  Lowercase letters, numbers, and underscore only. You can
                  change your current username here — this will become your
                  public creator username.
                </p>
              </div>
            </div>

            {/* Email + verification / password, depending on login state */}
            {!isLoggedIn ? (
              <div className="grid gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Email
                  </label>
                  <input
                    type="email"
                    className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      setEmailVerified(false);
                      setEmailSent(false);
                      setCodeInput("");
                    }}
                    required
                  />
                  {!emailVerified && email.length > 0 && (
                    <p className="mt-1 text-xs text-red-600">
                      You must verify your email before submitting.
                    </p>
                  )}
                  {emailVerified && (
                    <p className="mt-1 text-xs text-green-600">
                      Email verified ✓
                    </p>
                  )}
                </div>

                <div className="grid sm:grid-cols-3 gap-3 items-end">
                  <div className="sm:col-span-2">
                    <label className="block text-sm font-medium text-gray-700">
                      Verification code
                    </label>
                    <input
                      className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                      placeholder="123456"
                      value={codeInput}
                      onChange={(e) => setCodeInput(e.target.value)}
                      maxLength={6}
                    />
                    {emailSent && (
                      <p className="mt-1 text-xs text-gray-500">
                        Check your inbox for a 6-digit code (demo: 123456).
                      </p>
                    )}
                  </div>

                  <div className="flex flex-col gap-2">
                    <button
                      type="button"
                      onClick={handleSendCode}
                      disabled={!emailOk || sendingCode}
                      className={classNames(
                        "rounded-xl px-4 py-2 text-sm font-semibold",
                        emailOk && !sendingCode
                          ? "bg-brand-50 text-brand-700 border border-brand-100 hover:bg-brand-100"
                          : "bg-gray-100 text-gray-400 cursor-not-allowed"
                      )}
                    >
                      {sendingCode ? "Sending…" : "Send code"}
                    </button>
                    {emailSent && (
                      <button
                        type="button"
                        onClick={handleVerifyCode}
                        disabled={!codeInput || verifyingCode}
                        className={classNames(
                          "rounded-xl px-4 py-2 text-sm font-semibold",
                          codeInput && !verifyingCode
                            ? "bg-brand-600 text-white hover:bg-brand-700"
                            : "bg-gray-300 text-gray-600 cursor-not-allowed"
                        )}
                      >
                        {verifyingCode ? "Verifying…" : "Verify code"}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <div className="grid gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Email (linked to your account)
                  </label>
                  <input
                    type="email"
                    className="mt-1 w-full rounded-xl border px-3 py-2 bg-gray-50 text-gray-600 cursor-not-allowed"
                    value={effectiveEmail}
                    disabled
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    This is the email you use to log in. Creator earnings and
                    notifications will be tied to this account.
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Confirm your password
                  </label>
                  <input
                    type="password"
                    className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                    placeholder="Enter your account password"
                    value={passwordConfirm}
                    onChange={(e) => setPasswordConfirm(e.target.value)}
                    required
                  />
                  <p className="mt-1 text-xs text-gray-500">
                    For security, we&apos;ll verify this password with your
                    Faniko account before upgrading you to a creator.
                  </p>
                </div>
              </div>
            )}
          </section>

          {/* Monetization */}
          <section className="grid gap-4 rounded-2xl border p-5">
            <h2 className="text-lg font-semibold">Monetization</h2>

            <div className="grid sm:grid-cols-2 gap-4">
              <label className="flex items-center gap-2 rounded-xl border p-4 cursor-pointer">
                <input
                  type="radio"
                  name="accountType"
                  checked={accountType === "free"}
                  onChange={() => setAccountType("free")}
                />
                <div>
                  <div className="font-medium">Free to follow</div>
                  <div className="text-sm text-gray-600">
                    Earn from <strong>tips</strong>,{" "}
                    <strong>pay-per-view posts</strong> (price set per post),
                    and <strong>custom requests</strong>.
                  </div>
                </div>
              </label>

              <label className="flex items-center gap-2 rounded-xl border p-4 cursor-pointer">
                <input
                  type="radio"
                  name="accountType"
                  checked={accountType === "subscription"}
                  onChange={() => setAccountType("subscription")}
                />
                <div className="w-full">
                  <div className="font-medium">Subscription</div>
                  <div className="text-sm text-gray-600 mb-2">
                    Set a monthly price to unlock your main feed. You can still
                    use tips and PPV on top.
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-gray-500">$</span>
                    <input
                      type="number"
                      step={0.01}
                      className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                      value={price}
                      onChange={(e) =>
                        setPrice(e.target.value.replace(/^0+(\d)/, "$1"))
                      }
                    />
                  </div>
                  {!priceValid && (
                    <p className="mt-1 text-xs text-red-600">
                      Subscription price must be greater than 0.
                    </p>
                  )}
                </div>
              </label>
            </div>
          </section>

          {/* ID Verification */}
          <section className="grid gap-4 rounded-2xl border p-5">
            <h2 className="text-lg font-semibold">ID verification</h2>
            <p className="text-sm text-gray-600">
              We only use this to confirm you are 18+ and to prevent
              impersonation. Files are stored securely and never shown to fans.
            </p>

            <div className="grid sm:grid-cols-3 gap-4">
              <PrettyFileInput
                label="ID front"
                onChange={setIdFront}
                required
              />
              <PrettyFileInput label="ID back" onChange={setIdBack} required />
              <PrettyFileInput
                label="Selfie with ID"
                onChange={setSelfie}
                required
              />
            </div>

            <label className="flex items-start gap-2 mt-2">
              <input
                type="checkbox"
                checked={agree}
                onChange={(e) => setAgree(e.target.checked)}
              />
              <span className="text-sm text-gray-700">
                I confirm I am 18+ and agree to the Terms & Privacy Policy.
              </span>
            </label>
          </section>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
            <button
              type="submit"
              disabled={!canSubmit}
              className={classNames(
                "rounded-2xl px-6 py-3 text-white font-semibold",
                canSubmit
                  ? "bg-brand-600 hover:bg-brand-700"
                  : "bg-gray-300 cursor-not-allowed"
              )}
            >
              {submitting ? "Submitting…" : "Submit application"}
            </button>
            {!canSubmit && !submitting && submitError && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-100 rounded-lg px-3 py-2 max-w-md">
                {submitError}
              </p>
            )}
            {message && (
              <span className={messageClass}>{message}</span>
            )}
          </div>
        </form>
      </main>
    </div>
  );
}
