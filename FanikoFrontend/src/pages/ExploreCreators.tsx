import React, { useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";

type AccountType = "free" | "subscription";

type Creator = {
  id: number;
  displayName: string;
  username: string;
  accountType: AccountType;
  price?: number | null;
  createdAt?: string;
  status?: string;
};

export default function ExploreCreators() {
  const [creators, setCreators] = useState<Creator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | AccountType>("all");

  useEffect(() => {
    async function loadCreators() {
      try {
        setLoading(true);
        setError(null);

        const res = await fetch("http://localhost:4000/api/creators");
        if (!res.ok) throw new Error("Failed to load creators");

        const data = await res.json();
        setCreators(Array.isArray(data) ? data : []);
      } catch (err: any) {
        setError(err.message || "Something went wrong");
      } finally {
        setLoading(false);
      }
    }

    loadCreators();
  }, []);

  const filtered = useMemo(() => {
    let list = creators;

    if (filter !== "all") {
      list = list.filter((c) => c.accountType === filter);
    }

    if (search.trim().length > 0) {
      const q = search.toLowerCase();
      list = list.filter(
        (c) =>
          c.displayName?.toLowerCase().includes(q) ||
          c.username?.toLowerCase().includes(q)
      );
    }

    return list;
  }, [creators, filter, search]);

  return (
    <div className="min-h-screen bg-white">
      {/* Header */}
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
            <Link to="/creator" className="hover:text-brand-700">
              For creators
            </Link>
            <Link to="/creator/signup" className="hover:text-brand-700">
              Become a creator
            </Link>
          </nav>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-6xl mx-auto px-4 py-10">
        {/* Title + controls */}
        <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
              Explore <span className="text-brand-700">creators</span>
            </h1>
            <p className="mt-2 text-gray-600 max-w-xl">
              Discover Faniko creators. This is the MVP directory — later we can
              add tags, filters, and swipe-style discovery.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
            <div className="relative">
              <input
                type="text"
                placeholder="Search by name or @username"
                className="w-full sm:w-64 rounded-2xl border px-9 py-2 text-sm outline-none focus:ring-2 focus:ring-brand-400"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
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
                    d="M21 21l-4.35-4.35M11 18a7 7 0 100-14 7 7 0 000 14z"
                  />
                </svg>
              </span>
            </div>

            <div className="inline-flex rounded-full bg-gray-100 p-1 text-xs font-medium">
              <button
                type="button"
                onClick={() => setFilter("all")}
                className={
                  "px-3 py-1 rounded-full " +
                  (filter === "all"
                    ? "bg-white shadow-sm text-gray-900"
                    : "text-gray-500")
                }
              >
                All
              </button>
              <button
                type="button"
                onClick={() => setFilter("free")}
                className={
                  "px-3 py-1 rounded-full " +
                  (filter === "free"
                    ? "bg-white shadow-sm text-gray-900"
                    : "text-gray-500")
                }
              >
                Free
              </button>
              <button
                type="button"
                onClick={() => setFilter("subscription")}
                className={
                  "px-3 py-1 rounded-full " +
                  (filter === "subscription"
                    ? "bg-white shadow-sm text-gray-900"
                    : "text-gray-500")
                }
              >
                Subscription
              </button>
            </div>
          </div>
        </div>

        {/* States */}
        {loading && (
          <p className="mt-8 text-gray-500 text-sm">Loading creators…</p>
        )}

        {error && (
          <p className="mt-8 text-red-600 text-sm">
            {error} – is the backend running on{" "}
            <code>http://localhost:4000</code>?
          </p>
        )}

        {!loading && !error && creators.length === 0 && (
          <p className="mt-8 text-gray-500 text-sm">
            No creators yet. Be the first to{" "}
            <Link
              to="/creator/signup"
              className="text-brand-700 underline font-medium"
            >
              become a creator
            </Link>
            .
          </p>
        )}

        {!loading && !error && creators.length > 0 && filtered.length === 0 && (
          <p className="mt-8 text-gray-500 text-sm">
            No creators match your filters. Try clearing search or filter type.
          </p>
        )}

        {/* Grid */}
        {!loading && !error && filtered.length > 0 && (
          <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {filtered.map((c) => (
              <div
                key={c.id}
                className="rounded-2xl border border-gray-100 shadow-sm p-4 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-gradient-to-tr from-brand-400 to-brand-600 text-white flex items-center justify-center font-bold">
                      {c.displayName?.charAt(0)?.toUpperCase() ||
                        c.username?.charAt(0)?.toUpperCase() ||
                        "F"}
                    </div>
                    <div>
                      <div className="font-semibold truncate max-w-[10rem]">
                        {c.displayName || "Unnamed creator"}
                      </div>
                      <div className="text-xs text-gray-500 truncate max-w-[10rem]">
                        @{c.username}
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 text-xs inline-flex items-center gap-2 rounded-full bg-gray-50 px-3 py-1 text-gray-600">
                    {c.accountType === "free" ? (
                      <>
                        <span className="h-2 w-2 rounded-full bg-emerald-500" />
                        <span>Free to follow</span>
                        <span className="text-gray-400">
                          • tips + customs
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="h-2 w-2 rounded-full bg-brand-600" />
                        <span>Subscription</span>
                        {typeof c.price === "number" && (
                          <span className="text-gray-700">
                            • ${c.price.toFixed(2)}/mo
                          </span>
                        )}
                      </>
                    )}
                  </div>

                  <div className="mt-3 flex items-center justify-between text-[11px] text-gray-500">
                    <span
                      className={
                        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border " +
                        (c.status === "approved"
                          ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                          : "border-amber-200 bg-amber-50 text-amber-700")
                      }
                    >
                      <span className="h-1.5 w-1.5 rounded-full bg-current" />
                      {c.status === "approved" ? "Approved" : "Pending review"}
                    </span>
                    {c.createdAt && (
                      <span>
                        Joined{" "}
                        {new Date(c.createdAt).toLocaleDateString(undefined, {
                          year: "numeric",
                          month: "short",
                        })}
                      </span>
                    )}
                  </div>
                </div>

              <div className="mt-4">
  <Link
    to={`/c/${encodeURIComponent(c.username)}`}
    className="block w-full text-center rounded-xl border border-gray-200 text-xs font-semibold py-2 text-gray-700 hover:bg-gray-50"
  >
    View profile
  </Link>
</div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
