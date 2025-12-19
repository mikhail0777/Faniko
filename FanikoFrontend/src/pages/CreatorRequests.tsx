// src/pages/CreatorRequests.tsx
import React, { useState } from "react";
import { Link } from "react-router-dom";

type RequestStatus = "new" | "accepted" | "completed" | "declined";

type DemoRequest = {
  id: number;
  fanName: string;
  fanHandle?: string;
  budget: number;
  message: string;
  createdAt: string;
  status: RequestStatus;
};

const demoRequests: DemoRequest[] = [
  {
    id: 1,
    fanName: "Demo fan",
    fanHandle: "@fan001",
    budget: 50,
    message:
      "Can you do a 3–4 minute video answering some questions and giving a short shoutout?",
    createdAt: new Date().toISOString(),
    status: "new",
  },
  {
    id: 2,
    fanName: "Top supporter",
    fanHandle: "@whale23",
    budget: 120,
    message:
      "Custom photoset in the new outfit from your last post. Around 20 photos.",
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    status: "accepted",
  },
  {
    id: 3,
    fanName: "Anon",
    fanHandle: undefined,
    budget: 30,
    message:
      "Short voice note with my name in it. Nothing explicit, just playful.",
    createdAt: new Date(Date.now() - 3 * 86400000).toISOString(),
    status: "completed",
  },
];

function statusStyles(status: RequestStatus) {
  switch (status) {
    case "new":
      return "bg-amber-50 text-amber-700 border border-amber-100";
    case "accepted":
      return "bg-blue-50 text-blue-700 border border-blue-100";
    case "completed":
      return "bg-emerald-50 text-emerald-700 border border-emerald-100";
    case "declined":
      return "bg-gray-100 text-gray-600 border border-gray-200";
    default:
      return "bg-gray-100 text-gray-600 border border-gray-200";
  }
}

export default function CreatorRequests() {
  const [requests] = useState<DemoRequest[]>(demoRequests);
  const [filter, setFilter] = useState<"all" | RequestStatus>("all");

  const filtered = requests.filter((r) =>
    filter === "all" ? true : r.status === filter
  );

  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-5xl mx-auto px-4 pt-16 pb-24">
        <div className="flex items-center justify-between gap-3 mb-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-brand-600">
              Creator tools
            </p>
            <h1 className="mt-1 text-xl font-bold tracking-tight text-gray-900">
              Custom requests inbox
            </h1>
            <p className="mt-1 text-xs text-gray-500">
              This is where custom video/photo requests from fans will show up
              once we connect it to the backend.
            </p>
          </div>
          <Link
            to="/creator"
            className="hidden sm:inline-flex items-center rounded-full border border-gray-200 bg-white px-4 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-50"
          >
            Creator hub
          </Link>
        </div>

        <section className="grid gap-6 lg:grid-cols-[1.6fr,1fr]">
          {/* Requests list */}
          <div className="rounded-2xl bg-white border border-gray-100 p-4 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-semibold text-gray-900">
                  Requests ({filtered.length})
                </h2>
                <p className="text-[11px] text-gray-500">
                  In production, these would come from the “Request custom”
                  button on your profile.
                </p>
              </div>
              <div className="flex gap-1">
                {(["all", "new", "accepted", "completed"] as const).map(
                  (key) => (
                    <button
                      key={key}
                      onClick={() => setFilter(key)}
                      className={`px-2 py-1 rounded-full text-[11px] font-medium ${
                        filter === key
                          ? "bg-gray-900 text-white"
                          : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                      }`}
                    >
                      {key[0].toUpperCase() + key.slice(1)}
                    </button>
                  )
                )}
              </div>
            </div>

            {filtered.length === 0 ? (
              <p className="text-sm text-gray-500">
                No requests in this filter. Once fans start sending customs,
                they&apos;ll appear here.
              </p>
            ) : (
              <div className="space-y-3 max-h-[420px] overflow-auto pr-1">
                {filtered.map((req) => (
                  <div
                    key={req.id}
                    className="rounded-xl border border-gray-100 bg-gray-50 p-3 flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-semibold text-gray-900 truncate max-w-[11rem]">
                          {req.fanName}
                        </p>
                        {req.fanHandle && (
                          <span className="text-[11px] text-gray-500">
                            {req.fanHandle}
                          </span>
                        )}
                      </div>
                      <p className="mt-0.5 text-[11px] text-gray-500">
                        {new Date(req.createdAt).toLocaleString()}
                      </p>
                      <p className="mt-1 text-xs text-gray-700 line-clamp-3">
                        {req.message}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-1">
                      <span
                        className={
                          "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium " +
                          statusStyles(req.status)
                        }
                      >
                        {req.status[0].toUpperCase() + req.status.slice(1)}
                      </span>
                      <span className="text-xs font-semibold text-gray-900">
                        ${req.budget.toFixed(2)}
                      </span>
                      <button className="mt-1 rounded-full border border-gray-200 bg-white px-2 py-1 text-[11px] font-semibold text-gray-700 hover:bg-gray-50">
                        Open thread (future)
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Sidebar / explainer */}
          <aside className="space-y-4">
            <div className="rounded-2xl bg-white border border-gray-100 p-4 shadow-sm">
              <h2 className="text-sm font-semibold text-gray-900 mb-1">
                How this will work
              </h2>
              <p className="text-xs text-gray-600">
                When a fan taps “Request custom” on your profile, we&apos;ll:
              </p>
              <ul className="mt-2 text-xs text-gray-700 space-y-1.5">
                <li>• Collect their request details and budget</li>
                <li>• Create a request row linked to your account</li>
                <li>• Let you accept/decline and chat in a dedicated thread</li>
                <li>• Lock delivery + payment until you mark it completed</li>
              </ul>
            </div>

            <div className="rounded-2xl bg-gray-900 text-white p-4 shadow-sm text-xs">
              <h2 className="text-sm font-semibold mb-1">
                Roadmap (tied to your scaling plan)
              </h2>
              <ul className="space-y-1.5 text-gray-100">
                <li>• Real fan accounts & logins</li>
                <li>• Store requests and tips in the backend</li>
                <li>• Filter by high spenders / repeat buyers</li>
                <li>• Auto-reply templates and broadcast messages</li>
              </ul>
            </div>
          </aside>
        </section>
      </main>
    </div>
  );
}
