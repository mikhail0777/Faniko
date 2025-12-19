// src/pages/CreatorProfile.tsx
import React, { useEffect, useState, FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../AuthContext";

type AccountType = "free" | "subscription";
type Visibility = "free" | "ppv";

type Creator = {
  id: number;
  displayName: string;
  username: string;
  email?: string;
  accountType: AccountType;
  price?: number | null;
  createdAt?: string;
  status?: string;
};

type CreatorPost = {
  id: number;
  title: string;
  visibility: Visibility;
  price?: number | null;
  description?: string;
  createdAt?: string;
  mediaFilename?: string | null;
  mediaMime?: string | null;
  // backend like data
  likes?: number;
  likedBy?: string[];
};

// Frontend-friendly view of earnings; we’ll map backend → this
type EarningsBreakdown = {
  currency: string;
  monthToDate: number;
  last30Days: number;
  lifetime: number;
  sources: {
    subscriptions: number;
    ppv: number;
    tips: number;
    customRequests: number;
  };
};

function classNames(...c: Array<string | false | undefined>) {
  return c.filter(Boolean).join(" ");
}

export default function CreatorProfile() {
  const { username } = useParams<{ username: string }>();
  const { user } = useAuth();

  const [creator, setCreator] = useState<Creator | null>(null);
  const [posts, setPosts] = useState<CreatorPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Earnings state (subscriptions + PPV + tips + customs)
  const [earnings, setEarnings] = useState<EarningsBreakdown | null>(null);
  const [earningsLoading, setEarningsLoading] = useState(false);

  // Tip modal state
  const [tipOpen, setTipOpen] = useState(false);
  const [tipAmount, setTipAmount] = useState<string>("10.00");
  const [tipMessage, setTipMessage] = useState<string>("");
  const [activeTipPostId, setActiveTipPostId] = useState<number | null>(null);
  const [tipSubmitting, setTipSubmitting] = useState(false);
  const [tipError, setTipError] = useState<string | null>(null);

  // Custom request modal state (still fake)
  const [requestOpen, setRequestOpen] = useState(false);
  const [requestText, setRequestText] = useState("");
  const [requestBudget, setRequestBudget] = useState<string>("25.00");

  // Local like state per post
  // liked: whether THIS user has liked
  // count: current visible count
  const [likes, setLikes] = useState<
    Record<number, { liked: boolean; count: number }>
  >({});

  // PPV unlock state (per post, per session)
  const [unlocked, setUnlocked] = useState<Record<number, boolean>>({});
  const [unlockingPostId, setUnlockingPostId] = useState<number | null>(null);
  const [unlockError, setUnlockError] = useState<string | null>(null);

  // Subscription state (per session)
  const [subscribed, setSubscribed] = useState(false);
  const [subscribing, setSubscribing] = useState(false);
  const [subscribeError, setSubscribeError] = useState<string | null>(null);

  // Owner view toggle: controls ONLY blur/lock (creator vs fan preview)
  const [viewerMode, setViewerMode] = useState<"creator" | "fan">("creator");

  useEffect(() => {
    if (!username) return;

    async function loadData() {
      try {
        setLoading(true);
        setError(null);

        // 1) Load creator
        const creatorRes = await fetch(
          `http://localhost:4000/api/creators/${encodeURIComponent(username)}`
        );
        if (!creatorRes.ok) {
          if (creatorRes.status === 404) {
            throw new Error("Creator not found");
          }
          throw new Error("Failed to load creator");
        }
        const creatorData: Creator = await creatorRes.json();
        setCreator(creatorData);

        // 2) Load posts
        const postsRes = await fetch(
          `http://localhost:4000/api/creators/${encodeURIComponent(
            username
          )}/posts`
        );
        if (!postsRes.ok) {
          throw new Error("Failed to load posts");
        }
        const postsData: CreatorPost[] = await postsRes.json();
        setPosts(postsData);
      } catch (err: any) {
        console.error(err);
        setError(err.message || "Something went wrong");
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [username]);

  // Are we viewing our own creator profile?
  const isOwner =
    !!user &&
    !!username &&
    user.role === "creator" &&
    user.username.toLowerCase() === username.toLowerCase();

  // 🔹 Only the owner should load earnings
  useEffect(() => {
    if (!username || !isOwner) {
      // ensure fans don't see stale owner data
      setEarnings(null);
      setEarningsLoading(false);
      return;
    }

    async function loadEarnings() {
      try {
        setEarningsLoading(true);
        const earningsRes = await fetch(
          `http://localhost:4000/api/creators/${encodeURIComponent(
            username
          )}/earnings`
        );
        if (earningsRes.ok) {
          const raw = await earningsRes.json();
          const totals = raw?.totals || {};
          const converted: EarningsBreakdown = {
            currency: "USD",
            monthToDate: Number(totals.allTime || 0),
            last30Days: Number(totals.allTime || 0),
            lifetime: Number(totals.allTime || 0),
            sources: {
              subscriptions: Number(totals.subscriptions || 0),
              ppv: Number(totals.ppv || 0),
              tips: Number(totals.tips || 0),
              customRequests: 0,
            },
          };
          setEarnings(converted);
        } else {
          setEarnings(null);
        }
      } catch (e) {
        console.warn("Failed to load earnings snapshot:", e);
        setEarnings(null);
      } finally {
        setEarningsLoading(false);
      }
    }

    loadEarnings();
  }, [username, isOwner]);

  // When posts or user change, initialise like state (for heart color + count)
  useEffect(() => {
    if (!posts.length) return;

    const initial: Record<number, { liked: boolean; count: number }> = {};

    posts.forEach((p) => {
      const raw = p as any;
      const likesCount =
        typeof raw.likes === "number" ? Number(raw.likes) : 0;
      const likedBy: string[] | undefined = raw.likedBy;

      let liked = false;
      if (user && Array.isArray(likedBy)) {
        const me = user.username.toLowerCase();
        liked = likedBy.some((name) => String(name).toLowerCase() === me);
      }

      initial[p.id] = {
        liked,
        count: likesCount,
      };
    });

    setLikes(initial);
  }, [posts, user]);

  // Backend-driven like toggle
  async function handleToggleLike(postId: number) {
    if (!username) return;
    if (!user) {
      alert("You need to be logged in to like posts.");
      return;
    }

    try {
      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/posts/${postId}/like`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fanUsername: user.username,
          }),
        }
      );

      const data = await res.json();

      if (!res.ok) {
        console.error("Like error:", data?.error);
        alert(data?.error || "Failed to like this post.");
        return;
      }

      // Backend returns: { success, postId, likes, likedByMe }
      setLikes((prev) => ({
        ...prev,
        [postId]: {
          liked: !!data.likedByMe,
          count:
            typeof data.likes === "number"
              ? data.likes
              : prev[postId]?.count ?? 0,
        },
      }));
    } catch (err) {
      console.error(err);
      alert("Something went wrong while liking this post.");
    }
  }

  function openTipModalForPost(postId: number | null) {
    setActiveTipPostId(postId);
    setTipAmount("10.00");
    setTipMessage("");
    setTipError(null);
    setTipOpen(true);
  }

  async function handleTipSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username) return;

    const amountNum = Number(tipAmount || "0");
    if (Number.isNaN(amountNum) || amountNum <= 0) {
      alert("Please enter a valid tip amount.");
      return;
    }

    setTipSubmitting(true);
    setTipError(null);

    try {
      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/tips`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            amount: amountNum,
            message: tipMessage.trim(),
            fanUsername: user?.username ?? null,
            fanEmail: user?.email ?? null,
            postId: activeTipPostId,
          }),
        }
      );

      const data = await res.json();

      if (!res.ok) {
        setTipError(data?.error || "Failed to send tip. Please try again.");
        return;
      }

      alert(
        `Thanks! Your $${amountNum.toFixed(
          2
        )} tip was recorded (MVP, no real charge).`
      );

      setTipOpen(false);
      setActiveTipPostId(null);
      setTipMessage("");
      setTipAmount("10.00");
      setTipError(null);
    } catch (err: any) {
      console.error(err);
      setTipError("Something went wrong. Please try again.");
    } finally {
      setTipSubmitting(false);
    }
  }

  function handleFakeRequestSubmit(e: FormEvent) {
    e.preventDefault();

    if (!requestText.trim()) {
      alert("Please describe what you want.");
      return;
    }

    const budgetNum = Number(requestBudget || "0");
    if (Number.isNaN(budgetNum) || budgetNum <= 0) {
      alert("Please enter a valid budget.");
      return;
    }

    alert(
      `MVP: Sent custom request (Budget: $${budgetNum.toFixed(
        2
      )}). This would normally DM the creator.`
    );

    setRequestOpen(false);
    setRequestText("");
    setRequestBudget("25.00");
  }

  async function handleUnlockPost(postId: number) {
    if (!username) return;

    const post = posts.find((p) => p.id === postId);
    if (!post) {
      alert("Post not found.");
      return;
    }
    if (
      post.visibility !== "ppv" ||
      (typeof post.price === "number" ? post.price <= 0 : true)
    ) {
      alert("This post is not a paid PPV post.");
      return;
    }

    setUnlockingPostId(postId);
    setUnlockError(null);

    try {
      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/posts/${postId}/unlock`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fanUsername: user?.username ?? null,
            fanEmail: user?.email ?? null,
          }),
        }
      );

      const data = await res.json();

      if (!res.ok) {
        setUnlockError(data?.error || "Failed to unlock this post.");
        return;
      }

      setUnlocked((prev) => ({ ...prev, [postId]: true }));

      if (!data.alreadyUnlocked) {
        alert(
          `Unlocked this PPV post for $${post.price!.toFixed(
            2
          )} (MVP, no real charge).`
        );
      }
    } catch (err: any) {
      console.error(err);
      setUnlockError("Something went wrong while unlocking this post.");
    } finally {
      setUnlockingPostId(null);
    }
  }

  async function handleSubscribe() {
    if (!username || !creator) return;
    if (creator.accountType !== "subscription") return;

    setSubscribing(true);
    setSubscribeError(null);

    try {
      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/subscribe`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fanUsername: user?.username ?? null,
            fanEmail: user?.email ?? null,
          }),
        }
      );

      const data = await res.json();

      if (!res.ok) {
        setSubscribeError(
          data?.error || "Failed to start subscription. Please try again."
        );
        return;
      }

      setSubscribed(true);

      if (!data.alreadySubscribed) {
        alert(
          `Subscription started at $${creator.price?.toFixed(
            2
          )}/month (MVP, no real charge).`
        );
      }
    } catch (err: any) {
      console.error(err);
      setSubscribeError("Something went wrong. Please try again.");
    } finally {
      setSubscribing(false);
    }
  }

  function renderMedia(post: CreatorPost, isLocked: boolean) {
    if (!post.mediaFilename) {
      return (
        <span className="text-xs text-gray-500">
          {isLocked
            ? "Locked media (image/video)"
            : "Free preview media (placeholder)"}
        </span>
      );
    }

    const url = `http://localhost:4000/uploads/${post.mediaFilename}`;
    const isImage = post.mediaMime?.startsWith("image/");
    const isVideo = post.mediaMime?.startsWith("video/");

    if (isLocked) {
      if (isImage) {
        return (
          <img
            src={url}
            alt={post.title}
            className="h-full w-full object-cover blur-2xl"
          />
        );
      }
      if (isVideo) {
        return (
          <video
            className="h-full w-full object-cover blur-2xl"
            muted
            playsInline
          >
            <source src={url} />
            Your browser does not support the video tag.
          </video>
        );
      }
      return null;
    }

    if (isImage) {
      return (
        <img src={url} alt={post.title} className="h-full w-full object-cover" />
      );
    }

    if (isVideo) {
      // No-download-ish video configuration (MVP)
      return (
        <video
          className="h-full w-full object-cover"
          controls
          controlsList="nodownload noplaybackrate"
          onContextMenu={(e) => e.preventDefault()}
          playsInline
        >
          <source src={url} />
          Your browser does not support the video tag.
        </video>
      );
    }

    return (
      <span className="text-xs text-gray-500">
        Unsupported media type. (MVP)
      </span>
    );
  }

  if (!username) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-4xl px-4 py-10">
          <p className="text-sm text-gray-700">No creator username provided.</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-4xl px-4 py-10">
          <p className="text-sm text-gray-500">Loading creator profile…</p>
        </div>
      </div>
    );
  }

  if (error || !creator) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="mx-auto max-w-4xl px-4 py-10">
          <p className="text-sm text-red-600">
            {error || "Creator not found or failed to load."}
          </p>
          <Link
            to="/explore"
            className="mt-3 inline-flex items-center text-sm font-medium text-brand-600 hover:text-brand-700"
          >
            ← Back to explore
          </Link>
        </div>
      </div>
    );
  }

  const subscriptionLabel =
    creator.accountType === "subscription" && typeof creator.price === "number"
      ? `$${creator.price.toFixed(2)}/month`
      : "Free to follow";

  const earningsCurrency = earnings?.currency || "USD";

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="border-b border-gray-100 bg-white/70 backdrop-blur">
        <div className="mx-auto max-w-4xl px-4 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <Link
              to="/explore"
              className="inline-flex items-center rounded-full bg-gray-50 px-3 py-1 text-xs font-medium text-gray-600 hover:bg-gray-100"
            >
              ← Back
            </Link>
            <div>
              <p className="text-xs uppercase tracking-wide text-gray-500">
                Faniko Creator
              </p>
              <h1 className="text-lg font-semibold text-gray-900">
                {creator.displayName}{" "}
                <span className="text-sm font-normal text-gray-500">
                  @{creator.username}
                </span>
              </h1>
              {creator.status && (
                <p className="text-xs text-gray-500">
                  Status:{" "}
                  <span className="font-medium capitalize">
                    {creator.status}
                  </span>
                </p>
              )}
              {isOwner && (
                <p className="mt-1 text-[11px] text-gray-500">
                  You&apos;re viewing your public creator profile.
                </p>
              )}
            </div>
          </div>
          <div className="flex flex-col items-end gap-1">
            <p className="text-xs text-gray-500">Subscription</p>
            <p className="text-sm font-semibold text-brand-600">
              {subscriptionLabel}
            </p>
            {creator.createdAt && (
              <p className="text-[11px] text-gray-400">
                On Faniko since{" "}
                {new Date(creator.createdAt).toLocaleDateString()}
              </p>
            )}

            {/* Earnings mini-snapshot – ONLY visible to the creator */}
            {isOwner && (
              <div className="mt-1 rounded-lg bg-gray-50 px-2.5 py-1.5 text-right">
                <p className="text-[10px] text-gray-500">
                  Est. earnings this month
                </p>
                <p className="text-xs font-semibold text-gray-900">
                  {earningsLoading
                    ? "Calculating…"
                    : earnings
                    ? `${earningsCurrency} ${earnings.monthToDate.toFixed(2)}`
                    : `${earningsCurrency} 0.00`}
                </p>
                {earnings && (
                  <p className="text-[10px] text-gray-400">
                    Subs {earningsCurrency}{" "}
                    {earnings.sources.subscriptions.toFixed(0)} · PPV{" "}
                    {earningsCurrency} {earnings.sources.ppv.toFixed(0)} · Tips{" "}
                    {earningsCurrency} {earnings.sources.tips.toFixed(0)}
                  </p>
                )}
                <p className="mt-0.5 text-[10px] text-gray-400">
                  Visible only to you – fans can&apos;t see this.
                </p>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-6">
        {/* Top actions */}
        <section className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold text-gray-900">
              {isOwner ? "Your public profile" : `Support ${creator.username}`}
            </h2>
            <p className="text-xs text-gray-500">
              {isOwner
                ? "This is how fans see your page. Manage posts from your creator dashboard."
                : "Subscribe, tip, or request custom content. (MVP: no real payments yet.)"}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* View as toggle (only for owner) */}
            {isOwner && (
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-gray-500">View as</span>
                <div className="inline-flex rounded-full bg-gray-100 p-1">
                  <button
                    type="button"
                    onClick={() => setViewerMode("creator")}
                    className={classNames(
                      "px-3 py-1 text-[11px] font-semibold rounded-full transition",
                      viewerMode === "creator"
                        ? "bg-white text-gray-900 shadow-sm"
                        : "bg-transparent text-gray-500"
                    )}
                  >
                    Creator
                  </button>
                  <button
                    type="button"
                    onClick={() => setViewerMode("fan")}
                    className={classNames(
                      "px-3 py-1 text-[11px] font-semibold rounded-full transition",
                      viewerMode === "fan"
                        ? "bg-white text-gray-900 shadow-sm"
                        : "bg-transparent text-gray-500"
                    )}
                  >
                    Fan
                  </button>
                </div>
              </div>
            )}

            {/* Hide follow / tip / request / subscribe if owner */}
            {!isOwner && (
              <>
                <button
                  type="button"
                  className="rounded-full bg-gray-900 px-4 py-2 text-xs font-semibold text-white hover:bg-black"
                >
                  Follow (fake)
                </button>

                {creator.accountType === "subscription" && (
                  <button
                    type="button"
                    onClick={handleSubscribe}
                    disabled={subscribing || subscribed}
                    className={classNames(
                      "rounded-full px-4 py-2 text-xs font-semibold border",
                      subscribed
                        ? "bg-emerald-50 border-emerald-200 text-emerald-700 cursor-default"
                        : "bg-white border-brand-200 text-brand-700 hover:bg-brand-50"
                    )}
                  >
                    {subscribed
                      ? "Subscribed"
                      : subscribing
                      ? "Subscribing…"
                      : creator.price
                      ? `Subscribe $${creator.price.toFixed(2)}/month`
                      : "Subscribe"}
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => openTipModalForPost(null)}
                  className="rounded-full border border-brand-200 bg-white px-4 py-2 text-xs font-semibold text-brand-700 hover:bg-brand-50"
                >
                  Tip creator
                </button>
                <button
                  type="button"
                  onClick={() => setRequestOpen(true)}
                  className="rounded-full border border-gray-200 bg-white px-4 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-50"
                >
                  Request custom
                </button>
              </>
            )}
          </div>
        </section>

        {(subscribeError || unlockError) && (
          <p className="mb-4 text-xs text-red-600">
            {subscribeError || unlockError}
          </p>
        )}

        {/* Posts feed */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-gray-900">
              Posts ({posts.length})
            </h2>
            <p className="text-[11px] text-gray-500">
              {isOwner
                ? viewerMode === "creator"
                  ? "PPV posts appear unlocked to you. Fans will see them blurred until they pay."
                  : "You’re previewing this page as a fan. PPV posts are blurred and locked."
                : "PPV posts show a locked preview until you pay. (MVP)"}
            </p>
          </div>

          {posts.length === 0 ? (
            <p className="text-sm text-gray-500">
              This creator hasn&apos;t posted anything yet.
            </p>
          ) : (
            <div className="space-y-4">
              {posts.map((post) => {
                const isOwnerViewingAsCreator =
                  isOwner && viewerMode === "creator";
                const isOwnerViewingAsFan = isOwner && viewerMode === "fan";

                // Lock logic:
                // - Owner + "creator" view → never locked
                // - Owner + "fan" view → always locked (preview)
                // - Normal users → locked until unlocked[]
                let isLocked = false;
                if (post.visibility === "ppv") {
                  if (isOwnerViewingAsCreator) {
                    isLocked = false;
                  } else if (isOwnerViewingAsFan) {
                    isLocked = true;
                  } else {
                    isLocked = !unlocked[post.id];
                  }
                }

                const likeState = likes[post.id] || {
                  liked: false,
                  count:
                    typeof (post as any).likes === "number"
                      ? Number((post as any).likes)
                      : 0,
                };

                const canUnlock = !isOwner && post.visibility === "ppv";

                return (
                  <article
                    key={post.id}
                    className="rounded-2xl border border-gray-100 overflow-hidden bg-white shadow-sm"
                  >
                    {/* Card header */}
                    <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
                      <div>
                        <h3 className="text-sm font-semibold text-gray-900">
                          {post.title}
                        </h3>
                        {post.createdAt && (
                          <p className="text-xs text-gray-500">
                            {new Date(post.createdAt).toLocaleString()}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={classNames(
                            "inline-flex items-center rounded-full px-3 py-1 text-xs font-medium",
                            isLocked
                              ? "bg-amber-50 text-amber-700 border border-amber-100"
                              : "bg-emerald-50 text-emerald-700 border border-emerald-100"
                          )}
                        >
                          {post.visibility === "ppv" ? "PPV" : "Free"}
                        </span>
                        {post.visibility === "ppv" &&
                          typeof post.price === "number" && (
                            <span className="text-xs font-semibold text-gray-800">
                              ${post.price.toFixed(2)}
                            </span>
                          )}
                      </div>
                    </div>

                    {/* Media area */}
                    <div className="relative bg-gray-100 aspect-video flex items-center justify-center overflow-hidden">
                      {isLocked && (
                        <div className="absolute inset-0 bg-black/45 flex items-center justify-center">
                          <div className="text-center text-white px-4">
                            <p className="text-sm font-semibold">
                              Locked pay-per-view post
                            </p>
                            {typeof post.price === "number" && (
                              <p className="mt-1 text-xs">
                                Unlock for ${post.price.toFixed(2)} (MVP)
                              </p>
                            )}
                            <button
                              type="button"
                              onClick={() =>
                                canUnlock ? handleUnlockPost(post.id) : undefined
                              }
                              disabled={unlockingPostId === post.id || !canUnlock}
                              className="mt-3 rounded-2xl bg-white/90 text-gray-900 text-xs font-semibold px-4 py-2 hover:bg-white disabled:opacity-60"
                            >
                              {canUnlock
                                ? unlockingPostId === post.id
                                  ? "Unlocking…"
                                  : "Unlock post"
                                : "Unlock post (fan view)"}
                            </button>
                          </div>
                        </div>
                      )}

                      {renderMedia(post, isLocked)}
                    </div>

                    {/* Description */}
                    {post.description && (
                      <div className="px-4 py-3">
                        <p className="text-sm text-gray-700">
                          {post.description}
                        </p>
                      </div>
                    )}

                    {/* Likes row + actions */}
                    <div className="px-4 py-3 border-t border-gray-100 flex items-center justify-between">
                      {/* Small likes badge – visible to everyone (so creator can see count) */}
                      <div className="inline-flex items-center gap-1 text-[11px] text-gray-500">
                        <span
                          className={classNames(
                            "text-xs",
                            likeState.count > 0 ? "text-rose-500" : "text-gray-400"
                          )}
                        >
                          ♥
                        </span>
                        <span>{likeState.count}</span>
                        <span>likes</span>
                      </div>

                      {/* Full like + tip actions only for fans (not owner) */}
                      {!isOwner && (
                        <div className="flex items-center gap-4">
                          <button
                            type="button"
                            onClick={() => handleToggleLike(post.id)}
                            className={classNames(
                              "inline-flex items-center gap-1 text-xs font-semibold",
                              likeState.liked
                                ? "text-rose-600"
                                : "text-gray-500 hover:text-gray-700"
                            )}
                          >
                            <span>{likeState.liked ? "♥" : "♡"}</span>
                            <span>Like</span>
                          </button>

                          <button
                            type="button"
                            onClick={() => openTipModalForPost(post.id)}
                            className="inline-flex items-center gap-1 rounded-full border border-brand-200 px-3 py-1.5 text-[11px] font-semibold text-brand-700 hover:bg-brand-50"
                          >
                            Tip this post
                          </button>
                        </div>
                      )}
                    </div>
                  </article>
                );
              })}
            </div>
          )}

          <p className="mt-4 text-xs text-gray-500">
            In a full build, this feed would support comments, likes backed by
            the backend, real payments, and NSFW-toggle handling.
          </p>
        </section>
      </main>

      {/* Tip modal */}
      {tipOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl max-w-sm w-full p-6 shadow-lg">
            <h2 className="text-lg font-semibold">
              {activeTipPostId != null
                ? "Send a tip for this post"
                : "Send a tip to this creator"}
            </h2>
            <p className="mt-1 text-xs text-gray-500">
              MVP payments – this records a transaction on the backend but
              doesn&apos;t charge a real card.
            </p>
            <form onSubmit={handleTipSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Amount (USD)
                </label>
                <input
                  type="number"
                  min={1}
                  step={1}
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                  value={tipAmount}
                  onChange={(e) => setTipAmount(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Message (optional, max 500 characters)
                </label>
                <textarea
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400 text-sm"
                  rows={4}
                  maxLength={500}
                  value={tipMessage}
                  onChange={(e) => setTipMessage(e.target.value)}
                  placeholder="Say thanks, make a request, or leave a short note for the creator…"
                />
                <p className="mt-1 text-[11px] text-gray-400 text-right">
                  {tipMessage.length}/500
                </p>
              </div>

              {tipError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-100 rounded-md px-3 py-2">
                  {tipError}
                </p>
              )}

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setTipOpen(false);
                    setActiveTipPostId(null);
                    setTipMessage("");
                    setTipAmount("10.00");
                    setTipError(null);
                  }}
                  className="rounded-xl border border-gray-200 px-3 py-2 text-xs font-semibold text-gray-600 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={tipSubmitting}
                  className="rounded-xl bg-brand-600 px-4 py-2 text-xs font-semibold text-white hover:bg-brand-700 disabled:opacity-60"
                >
                  {tipSubmitting ? "Sending…" : "Send tip"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Custom request modal */}
      {requestOpen && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/40">
          <div className="bg-white rounded-2xl max-w-sm w-full p-6 shadow-lg">
            <h2 className="text-lg font-semibold">Request custom content</h2>
            <p className="mt-1 text-xs text-gray-500">
              Describe what you want and your budget. In the full version this
              would DM the creator.
            </p>
            <form onSubmit={handleFakeRequestSubmit} className="mt-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  What are you looking for?
                </label>
                <textarea
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400 text-sm"
                  rows={4}
                  value={requestText}
                  onChange={(e) => setRequestText(e.target.value)}
                  placeholder="Example: 2-minute shoutout video mentioning my username…"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Budget (USD)
                </label>
                <input
                  type="number"
                  min={1}
                  step={1}
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                  value={requestBudget}
                  onChange={(e) => setRequestBudget(e.target.value)}
                />
              </div>

              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setRequestOpen(false)}
                  className="rounded-xl border border-gray-200 px-3 py-2 text-xs font-semibold text-gray-600 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded-xl bg-brand-600 px-4 py-2 text-xs font-semibold text-white hover:bg-brand-700"
                >
                  Send request (fake)
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

