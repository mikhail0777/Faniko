import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../AuthContext";

type PreviewCreator = {
  username: string;
  name: string;
  tagline: string;
  emoji: string;
};

const previewCreators: PreviewCreator[] = [
  {
    username: "bruna_fit",
    name: "Bruna • Training Logs",
    tagline: "Gym vlogs, form checks & weekly programs.",
    emoji: "🏋️‍♀️",
  },
  {
    username: "coach_ari",
    name: "Coach Ari",
    tagline: "Behind-the-scenes from camps, fight breakdowns & Q&A.",
    emoji: "🥊",
  },
  {
    username: "studio_nova",
    name: "Studio Nova",
    tagline: "Photo drops, BTS shoots & editing breakdowns.",
    emoji: "📸",
  },
];

export default function Home() {
  const { user } = useAuth();
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    const id = setInterval(
      () => setActiveIndex((prev) => (prev + 1) % previewCreators.length),
      4000
    );
    return () => clearInterval(id);
  }, []);

  const active = previewCreators[activeIndex];

  const isCreator = user?.role === "creator";

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Simple top header: logo only */}
      <header className="border-b border-gray-100 bg-white">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-2xl bg-gradient-to-br from-purple-500 to-indigo-500 flex items-center justify-center text-white text-lg font-bold">
              f
            </div>
            <span className="font-extrabold text-xl tracking-tight">
              Faniko
            </span>
          </div>
        </div>
      </header>

      {/* Main hero */}
      <main className="flex-1">
        <section className="max-w-6xl mx-auto px-4 py-12 grid gap-10 lg:grid-cols-2 items-center">
          {/* Left */}
          <div>
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-gray-900">
              Follow your favourite creators in one place.
            </h1>
            <p className="mt-4 text-sm sm:text-base text-gray-600 max-w-xl">
              Faniko lets you unlock exclusive posts, PPV drops and
              behind-the-scenes content from the people you already watch on
              TikTok, Instagram and YouTube. No clutter, no weird ads — just you
              and your creators.
            </p>

            {/* CTA area changes based on auth state */}
            {!user ? (
              <>
                {/* LOGGED OUT: big Sign up / Log in / Explore */}
                <div className="mt-6 flex flex-wrap gap-3">
                  <Link
                    to="/signup"
                    className="inline-flex items-center justify-center rounded-2xl bg-brand-600 text-white px-5 py-2.5 text-sm font-semibold shadow-sm hover:bg-brand-700"
                  >
                    Sign up
                  </Link>
                  <Link
                    to="/login"
                    className="inline-flex items-center justify-center rounded-2xl border border-gray-300 text-gray-900 px-5 py-2.5 text-sm font-semibold bg-white hover:bg-gray-50"
                  >
                    Log in
                  </Link>
                  <Link
                    to="/explore"
                    className="inline-flex items-center justify-center rounded-2xl border border-transparent px-5 py-2.5 text-sm font-semibold text-brand-700 hover:bg-brand-50"
                  >
                    Explore creators
                  </Link>
                </div>

                <div className="mt-4">
                  <Link
                    to="/creator"
                    className="text-xs font-semibold text-gray-700 underline underline-offset-4"
                  >
                    Are you a creator? Learn how Faniko works for you.
                  </Link>
                </div>
              </>
            ) : (
              <>
                {/* LOGGED IN: replace buttons with relevant actions */}
                <div className="mt-6 grid gap-3 sm:grid-cols-2">
                  {isCreator ? (
                    <>
                      <Link
                        to={`/creator/${user.username}/dashboard`}
                        className="inline-flex items-center justify-center rounded-2xl bg-gray-900 text-white px-5 py-2.5 text-sm font-semibold shadow-sm hover:bg-gray-800"
                      >
                        Go to your dashboard
                      </Link>
                      <Link
                        to={`/c/${user.username}`}
                        className="inline-flex items-center justify-center rounded-2xl border border-gray-300 text-gray-900 px-5 py-2.5 text-sm font-semibold bg-white hover:bg-gray-50"
                      >
                        View your public profile
                      </Link>
                      <Link
                        to="/explore"
                        className="inline-flex items-center justify-center rounded-2xl border border-transparent px-5 py-2.5 text-sm font-semibold text-brand-700 hover:bg-brand-50 sm:col-span-2"
                      >
                        Explore other creators
                      </Link>
                    </>
                  ) : (
                    <>
                      <Link
                        to="/explore"
                        className="inline-flex items-center justify-center rounded-2xl bg-brand-600 text-white px-5 py-2.5 text-sm font-semibold shadow-sm hover:bg-brand-700"
                      >
                        Continue exploring creators
                      </Link>
                      <button
                        type="button"
                        className="inline-flex items-center justify-center rounded-2xl border border-gray-300 text-gray-900 px-5 py-2.5 text-sm font-semibold bg-white cursor-default"
                      >
                        Your account (more coming soon)
                      </button>
                    </>
                  )}
                </div>

                {!isCreator && (
                  <div className="mt-4">
                    <Link
                      to="/creator"
                      className="text-xs font-semibold text-gray-700 underline underline-offset-4"
                    >
                      Want to earn as a creator? Learn how Faniko works for you.
                    </Link>
                  </div>
                )}
              </>
            )}

            <p className="mt-6 text-xs text-gray-500">
              Faniko is in early beta. Some features are limited while we
              onboard our first creators.
            </p>
          </div>

          {/* Right: rotating preview card */}
          <div className="hidden lg:block">
            <Link
              to={`/c/${active.username}`}
              className="block rounded-3xl border border-gray-200 bg-white shadow-sm p-4 hover:shadow-md transition-shadow"
            >
              <div className="text-xs text-gray-500 mb-2">
                Preview of a creator profile • Click to view
              </div>
              <div className="rounded-2xl bg-gradient-to-br from-purple-50 via-white to-indigo-50 p-4 h-[320px] flex flex-col">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-full bg-white flex items-center justify-center text-xl">
                    {active.emoji}
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-900">
                      {active.name}
                    </p>
                    <p className="text-xs text-gray-500">@{active.username}</p>
                  </div>
                </div>

                <div className="mt-4 text-xs text-gray-600">
                  {active.tagline}
                </div>

                <div className="mt-6 space-y-3 text-xs text-gray-500 flex-1">
                  <div className="h-16 rounded-xl bg-white/70 border border-gray-100 flex items-center justify-center">
                    Sample post preview (blurred until unlocked)
                  </div>
                  <div className="h-16 rounded-xl bg-white/70 border border-gray-100 flex items-center justify-center">
                    PPV drop • Tap to unlock
                  </div>
                  <div className="h-16 rounded-xl bg-white/70 border border-gray-100 flex items-center justify-center">
                    Chat bubble • DMs with your fans
                  </div>
                </div>

                <div className="mt-4 flex justify-between items-center">
                  <button
                    type="button"
                    className="rounded-2xl bg-gray-900 text-white px-4 py-1.5 text-xs font-semibold"
                  >
                    View profile
                  </button>
                  <div className="flex gap-1">
                    {previewCreators.map((c, i) => (
                      <span
                        key={c.username}
                        className={`h-1.5 w-1.5 rounded-full ${
                          i === activeIndex ? "bg-purple-600" : "bg-gray-300"
                        }`}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </Link>
          </div>
        </section>
      </main>
    </div>
  );
}

