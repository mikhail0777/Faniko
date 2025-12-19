// src/pages/CreatorLanding.tsx
import React from "react";
import { Link } from "react-router-dom";

export default function CreatorLanding() {
  return (
    <div className="min-h-screen bg-white">
      {/* Nav */}
      <header className="border-b border-gray-100">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/faniko-logo.svg" alt="Faniko" className="h-8 w-8" />
            <span className="font-extrabold text-xl tracking-tight">Faniko</span>
          </div>
          <nav className="hidden sm:flex items-center gap-6 text-sm">
            <Link to="/" className="hover:text-brand-700">
              Home
            </Link>
            <a href="#" className="hover:text-brand-700">
              Pricing
            </a>
            <a href="#" className="hover:text-brand-700">
              Safety
            </a>
            <a href="#" className="hover:text-brand-700">
              Login
            </a>
            <Link
              to="/creator/signup"
              className="rounded-xl bg-gray-900 text-white px-4 py-2 hover:bg-black"
            >
              Sign up
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-6xl mx-auto px-4 py-16 sm:py-24">
        <div className="grid md:grid-cols-2 gap-10 items-center">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full bg-brand-50 text-brand-700 px-3 py-1 text-xs font-semibold">
              New • Earn more
            </div>
            <h1 className="mt-4 text-4xl sm:text-5xl font-extrabold leading-tight tracking-tight">
              The creator platform that{" "}
              <span className="text-brand-700">pays you more</span>.
            </h1>
            <p className="mt-4 text-gray-600 max-w-prose">
              Keep <strong>90%</strong> of your earnings with low fees, instant
              payouts, and tools built for fan communities. Start with private
              posts, subscriptions, and tips—expand as you grow.
            </p>
            <div className="mt-8 flex items-center gap-4">
              <Link
                to="/creator/signup"
                className="inline-flex items-center gap-2 rounded-2xl bg-brand-600 hover:bg-brand-700 text-white px-6 py-3 text-sm font-semibold transition"
              >
                Become a creator
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="16"
                  height="16"
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M13.5 4.5L21 12l-7.5 7.5M21 12H3"
                  />
                </svg>
              </Link>

              {/* 🔹 THIS is the button you’re clicking */}
              <Link
                to="/explore"
                className="inline-flex items-center gap-2 text-brand-700 hover:text-brand-900 font-semibold"
              >
                Browse creators
              </Link>
            </div>
            <p className="mt-3 text-xs text-gray-500">
              By continuing you agree to our Terms and confirm you are 18+ as a
              creator.
            </p>
          </div>

          {/* Preview card */}
          <div className="relative">
            <div className="absolute -inset-6 bg-gradient-to-tr from-brand-200 to-brand-400 blur-3xl opacity-20 rounded-3xl" />
            <div className="relative rounded-3xl border border-gray-100 shadow-lg overflow-hidden">
              <div className="p-4 bg-gray-50 border-b border-gray-100 flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-red-400" />
                <div className="h-3 w-3 rounded-full bg-yellow-400" />
                <div className="h-3 w-3 rounded-full bg-green-400" />
                <span className="ml-3 text-xs text-gray-500">
                  Creator dashboard preview
                </span>
              </div>
              <div className="p-6 grid gap-4 bg-white">
                <div className="grid sm:grid-cols-3 gap-4">
                  <div className="rounded-2xl bg-brand-600 text-white p-4">
                    <div className="text-xs opacity-90">This month</div>
                    <div className="text-2xl font-extrabold">$4,820</div>
                    <div className="text-xs opacity-90">+18% vs last</div>
                  </div>
                  <div className="rounded-2xl border p-4">
                    <div className="text-xs text-gray-500">Subscribers</div>
                    <div className="text-xl font-bold">1,243</div>
                  </div>
                  <div className="rounded-2xl border p-4">
                    <div className="text-xs text-gray-500">Payout next</div>
                    <div className="text-xl font-bold">$1,120</div>
                  </div>
                </div>
                <div className="rounded-2xl border p-4">
                  <div className="text-sm font-semibold mb-2">Recent posts</div>
                  <div className="grid sm:grid-cols-3 gap-3">
                    <div className="aspect-video rounded-xl bg-gray-100" />
                    <div className="aspect-video rounded-xl bg-gray-100" />
                    <div className="aspect-video rounded-xl bg-gray-100" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Value props */}
      <section className="bg-gray-50 border-y border-gray-100">
        <div className="max-w-6xl mx-auto px-4 py-14 grid md:grid-cols-3 gap-8">
          <div>
            <div className="text-brand-700 font-semibold">90% payout</div>
            <p className="text-gray-600 mt-1">
              Creators keep more with our 10% platform fee and transparent
              payouts.
            </p>
          </div>
          <div>
            <div className="text-brand-700 font-semibold">Own your audience</div>
            <p className="text-gray-600 mt-1">
              Export emails and analytics to grow your business beyond the
              platform.
            </p>
          </div>
          <div>
            <div className="text-brand-700 font-semibold">Safe & compliant</div>
            <p className="text-gray-600 mt-1">
              KYC for creators, 18+ disclaimers for viewers, and robust content
              controls.
            </p>
          </div>
        </div>
      </section>

      <footer className="max-w-6xl mx-auto px-4 py-10 text-sm text-gray-500">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <img src="/faniko-logo.svg" className="h-6 w-6" alt="Faniko" />
            <span>© {new Date().getFullYear()} Faniko</span>
          </div>
          <div className="flex items-center gap-4">
            <a href="#" className="hover:text-gray-800">
              Terms
            </a>
            <a href="#" className="hover:text-gray-800">
              Privacy
            </a>
            <a href="#" className="hover:text-gray-800">
              Support
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

