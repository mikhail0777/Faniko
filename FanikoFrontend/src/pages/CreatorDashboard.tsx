// src/pages/CreatorDashboard.tsx
import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

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

  // NEW: like info from backend (optional)
  likes?: number;
  likedBy?: string[];
};

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

export default function CreatorDashboard() {
  const { username } = useParams<{ username: string }>();

  const [creator, setCreator] = useState<Creator | null>(null);
  const [posts, setPosts] = useState<CreatorPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // create-post form state
  const [title, setTitle] = useState("");
  const [visibility, setVisibility] = useState<Visibility>("free");
  const [price, setPrice] = useState<string>("9.99");
  const [description, setDescription] = useState("");
  const [mediaFile, setMediaFile] = useState<File | null>(null);

  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  // earnings state
  const [earnings, setEarnings] = useState<EarningsBreakdown | null>(null);
  const [earningsLoading, setEarningsLoading] = useState(false);
  const [earningsError, setEarningsError] = useState<string | null>(null);

  // 🔹 profile edit state (free ↔ subscription + price)
  const [accountTypeForm, setAccountTypeForm] = useState<AccountType>("free");
  const [subscriptionPriceForm, setSubscriptionPriceForm] =
    useState<string>("9.99");
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileMessage, setProfileMessage] = useState<string | null>(null);

  // 🔹 post edit state
  const [editingPostId, setEditingPostId] = useState<number | null>(null);
  const [editTitle, setEditTitle] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editVisibility, setEditVisibility] = useState<Visibility>("free");
  const [editPrice, setEditPrice] = useState<string>("0");
  const [editSaving, setEditSaving] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);

  useEffect(() => {
    if (!username) return;

    async function loadData() {
      try {
        setLoading(true);
        setError(null);

        // load creator
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

        // initialise profile-edit form from creator data
        setAccountTypeForm(creatorData.accountType);
        if (
          creatorData.accountType === "subscription" &&
          typeof creatorData.price === "number"
        ) {
          setSubscriptionPriceForm(creatorData.price.toFixed(2));
        } else {
          setSubscriptionPriceForm("9.99");
        }

        // load posts
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

        // load earnings
        try {
          setEarningsLoading(true);
          setEarningsError(null);

          const earningsRes = await fetch(
            `http://localhost:4000/api/creators/${encodeURIComponent(
              username
            )}/earnings`
          );

          if (!earningsRes.ok) {
            // don't kill dashboard if this fails
            setEarnings(null);
            try {
              const data = await earningsRes.json();
              if (data?.error) setEarningsError(data.error);
            } catch {
              /* ignore */
            }
          } else {
            const raw = await earningsRes.json();
            const totals = raw?.totals || {};

            const converted: EarningsBreakdown = {
              currency: "USD",
              monthToDate: Number(totals.allTime || 0), // MVP: same bucket
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
          }
        } catch (e: any) {
          console.warn("Failed to load earnings:", e);
          setEarnings(null);
          setEarningsError("Could not load earnings right now.");
        } finally {
          setEarningsLoading(false);
        }
      } catch (err: any) {
        setError(err.message || "Something went wrong");
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [username]);

  const canSubmit =
    title.trim().length > 0 &&
    (visibility === "free" || (visibility === "ppv" && Number(price) > 0)) &&
    !submitting;

  async function handleCreatePost(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !canSubmit) return;

    setSubmitting(true);
    setMessage(null);

    try {
      const formData = new FormData();
      formData.append("title", title.trim());
      formData.append("visibility", visibility);
      formData.append("description", description.trim());

      if (visibility === "ppv") {
        formData.append("price", price);
      }

      if (mediaFile) {
        formData.append("media", mediaFile); // must match backend .single("media")
      }

      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/posts`,
        {
          method: "POST",
          body: formData,
        }
      );

      if (!res.ok) {
        let errText = "Failed to create post";
        try {
          const data = await res.json();
          if (data.error) errText = data.error;
        } catch {
          // ignore
        }
        throw new Error(errText);
      }

      const data = await res.json();

      // prepend new post
      setPosts((prev) => [data.post, ...prev]);

      // reset form
      setTitle("");
      setDescription("");
      setVisibility("free");
      setPrice("9.99");
      setMediaFile(null);
      setMessage("Post created!");
    } catch (err: any) {
      setMessage(err.message || "Something went wrong.");
    } finally {
      setSubmitting(false);
    }
  }

  // 🔹 save profile (free/subscription + price)
  async function handleSaveProfile(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !creator) return;

    setProfileSaving(true);
    setProfileMessage(null);

    try {
      const body: any = {
        accountType: accountTypeForm,
      };

      if (accountTypeForm === "subscription") {
        body.price = subscriptionPriceForm;
      }

      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(username)}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        }
      );

      if (!res.ok) {
        let msg = "Failed to update profile";
        try {
          const data = await res.json();
          if (data.error) msg = data.error;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }

      const data = await res.json();
      const updated: Creator = data.creator;

      setCreator(updated);
      setProfileMessage("Profile updated.");
      // sync form state with API response
      setAccountTypeForm(updated.accountType);
      if (
        updated.accountType === "subscription" &&
        typeof updated.price === "number"
      ) {
        setSubscriptionPriceForm(updated.price.toFixed(2));
      } else {
        setSubscriptionPriceForm("9.99");
      }
    } catch (err: any) {
      setProfileMessage(err.message || "Something went wrong.");
    } finally {
      setProfileSaving(false);
    }
  }

  // 🔹 start editing a specific post
  function handleStartEditPost(post: CreatorPost) {
    setEditingPostId(post.id);
    setEditTitle(post.title || "");
    setEditDescription(post.description || "");
    setEditVisibility(post.visibility);
    if (post.visibility === "ppv" && typeof post.price === "number") {
      setEditPrice(post.price.toFixed(2));
    } else {
      setEditPrice("9.99");
    }
    setEditError(null);
  }

  function handleCancelEditPost() {
    setEditingPostId(null);
    setEditError(null);
    setEditSaving(false);
  }

  async function handleSavePostEdit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || editingPostId == null) return;

    setEditSaving(true);
    setEditError(null);

    try {
      const body: any = {
        title: editTitle.trim(),
        description: editDescription.trim(),
        visibility: editVisibility,
      };
      if (editVisibility === "ppv") {
        body.price = editPrice;
      }

      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/posts/${editingPostId}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        }
      );

      if (!res.ok) {
        let msg = "Failed to update post";
        try {
          const data = await res.json();
          if (data.error) msg = data.error;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }

      const data = await res.json();
      const updatedPost: CreatorPost = data.post;

      setPosts((prev) =>
        prev.map((p) => (p.id === updatedPost.id ? updatedPost : p))
      );
      setEditingPostId(null);
    } catch (err: any) {
      setEditError(err.message || "Something went wrong.");
    } finally {
      setEditSaving(false);
    }
  }

  // 🔹 delete a post
  async function handleDeletePost(postId: number) {
    if (!username) return;

    const ok = window.confirm(
      "Delete this post? This can't be undone in this MVP."
    );
    if (!ok) return;

    try {
      const res = await fetch(
        `http://localhost:4000/api/creators/${encodeURIComponent(
          username
        )}/posts/${postId}`,
        {
          method: "DELETE",
        }
      );

      if (!res.ok) {
        let msg = "Failed to delete post.";
        try {
          const data = await res.json();
          if (data.error) msg = data.error;
        } catch {
          /* ignore */
        }
        throw new Error(msg);
      }

      // remove from local state
      setPosts((prev) => prev.filter((p) => p.id !== postId));
    } catch (err: any) {
      alert(err.message || "Could not delete post.");
    }
  }

  const totalPosts = posts.length;
  const freeCount = posts.filter((p) => p.visibility === "free").length;
  const ppvCount = posts.filter((p) => p.visibility === "ppv").length;

  const earningsCurrency = earnings?.currency || "USD";
  const monthToDate = earnings?.monthToDate ?? 0;
  const last30 = earnings?.last30Days ?? 0;
  const lifetime = earnings?.lifetime ?? 0;

  // NEW: most liked post for overview widget
  const mostLikedPost: CreatorPost | null =
    posts.length === 0
      ? null
      : posts.reduce<CreatorPost | null>((best, post) => {
          const currentLikes =
            typeof post.likes === "number" ? post.likes : 0;
          const bestLikes =
            best && typeof best.likes === "number" ? best.likes : 0;
          if (!best || currentLikes > bestLikes) return post;
          return best;
        }, null);

  if (!username) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-4xl mx-auto px-4 py-10">
          <p className="text-sm text-gray-600">No creator username provided.</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-4xl mx-auto px-4 py-10">
          <p className="text-sm text-gray-500">Loading dashboard…</p>
        </div>
      </div>
    );
  }

  if (error || !creator) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="max-w-4xl mx-auto px-4 py-10">
          <p className="text-sm text-red-600">
            {error || "Creator not found or failed to load."}
          </p>
          <Link
            to="/creator"
            className="mt-3 inline-flex items-center text-sm font-medium text-brand-600 hover:text-brand-700"
          >
            ← Back to creator home
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="border-b border-gray-100 bg-white">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src="/faniko-logo.svg" alt="Faniko" className="h-8 w-8" />
            <span className="font-extrabold text-xl tracking-tight">
              Faniko
            </span>
          </div>
          <nav className="hidden sm:flex items-center gap-6 text-sm">
            <Link to="/" className="hover:text-brand-700">
              Home
            </Link>
            <Link to="/explore" className="hover:text-brand-700">
              Explore
            </Link>
            <Link
              to={`/c/${encodeURIComponent(username)}`}
              className="hover:text-brand-700"
            >
              View profile
            </Link>
          </nav>
        </div>
      </header>

      {/* Main grid */}
      <main className="max-w-6xl mx-auto px-4 py-8 grid gap-8 lg:grid-cols-[1.4fr,1fr]">
        {/* LEFT: create post + posts list */}
        <section className="space-y-6">
          {/* Creator info + profile edit */}
          <div className="rounded-2xl bg-white border border-gray-100 p-5 shadow-sm">
            <h1 className="text-xl font-bold tracking-tight">
              Creator dashboard
            </h1>
            <p className="mt-1 text-sm text-gray-600">
              Posting as{" "}
              <span className="font-semibold">
                {creator.displayName || creator.username}
              </span>{" "}
              (@{creator.username})
            </p>
            {creator.status && (
              <p className="mt-1 text-xs text-gray-500">
                Status:{" "}
                <span className="font-medium capitalize">
                  {creator.status}
                </span>
              </p>
            )}

            {/* Profile edit section */}
            <form
              onSubmit={handleSaveProfile}
              className="mt-4 border-t border-gray-100 pt-3 space-y-3"
            >
              <div className="flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  Control whether your profile is free or pay-to-follow.
                </p>
                {profileMessage && (
                  <span className="text-[11px] text-emerald-600">
                    {profileMessage}
                  </span>
                )}
              </div>

              <div className="grid sm:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <span className="block text-xs font-medium text-gray-700">
                    Profile type
                  </span>
                  <label className="flex items-center gap-2 rounded-xl border px-3 py-1.5 cursor-pointer text-xs">
                    <input
                      type="radio"
                      name="accountType"
                      checked={accountTypeForm === "free"}
                      onChange={() => setAccountTypeForm("free")}
                    />
                    <span>Free to follow</span>
                  </label>
                  <label className="flex items-center gap-2 rounded-xl border px-3 py-1.5 cursor-pointer text-xs">
                    <input
                      type="radio"
                      name="accountType"
                      checked={accountTypeForm === "subscription"}
                      onChange={() => setAccountTypeForm("subscription")}
                    />
                    <span>Paid subscription</span>
                  </label>
                </div>

                {accountTypeForm === "subscription" && (
                  <div>
                    <label className="block text-xs font-medium text-gray-700">
                      Subscription price (USD)
                    </label>
                    <input
                      type="number"
                      min={1}
                      step={0.01}
                      className="mt-1 w-full rounded-xl border px-3 py-1.5 outline-none focus:ring-2 focus:ring-brand-400 text-sm"
                      value={subscriptionPriceForm}
                      onChange={(e) => setSubscriptionPriceForm(e.target.value)}
                    />
                    <p className="mt-1 text-[11px] text-gray-500">
                      Fans will pay this monthly to subscribe.
                    </p>
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={profileSaving}
                className={classNames(
                  "inline-flex items-center rounded-2xl px-4 py-1.5 text-xs font-semibold",
                  profileSaving
                    ? "bg-gray-300 text-gray-600 cursor-not-allowed"
                    : "bg-gray-900 text-white hover:bg-black"
                )}
              >
                {profileSaving ? "Saving…" : "Save profile settings"}
              </button>
            </form>
          </div>

          {/* Create post */}
          <div className="rounded-2xl bg-white border border-gray-100 p-5 shadow-sm">
            <h2 className="text-sm font-semibold text-gray-800 mb-3">
              Create a new post
            </h2>

            {message && (
              <div
                className={classNames(
                  "mb-3 rounded-xl px-3 py-2 text-xs",
                  message.toLowerCase().includes("fail") ||
                    message.toLowerCase().includes("error")
                    ? "bg-red-50 border border-red-100 text-red-700"
                    : "bg-emerald-50 border border-emerald-100 text-emerald-700"
                )}
              >
                {message}
              </div>
            )}

            <form onSubmit={handleCreatePost} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Title
                </label>
                <input
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                  placeholder="Example: Cosplay set #3"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Description
                </label>
                <textarea
                  className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400 text-sm"
                  rows={3}
                  placeholder="Short caption or description of the content."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>

              {/* Media upload */}
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Media (image or video)
                </label>
                <label className="mt-1 inline-flex items-center gap-2 rounded-xl border px-4 py-2 cursor-pointer hover:bg-gray-50 text-sm">
                  <input
                    type="file"
                    accept="image/*,video/*"
                    className="sr-only"
                    onChange={(e) => {
                      const file = e.target.files?.[0] || null;
                      setMediaFile(file);
                    }}
                  />
                  <span className="text-xs font-medium text-gray-700">
                    {mediaFile ? "Change file" : "Choose file"}
                  </span>
                  <span className="text-xs text-gray-500">
                    {mediaFile ? `• ${mediaFile.name}` : "PNG/JPG/MP4 etc."}
                  </span>
                </label>
              </div>

              <div className="grid sm:grid-cols-2 gap-4 items-end">
                <div className="space-y-2">
                  <span className="block text-sm font-medium text-gray-700">
                    Visibility
                  </span>
                  <label className="flex items-center gap-2 rounded-xl border px-3 py-2 cursor-pointer text-sm">
                    <input
                      type="radio"
                      name="visibility"
                      checked={visibility === "free"}
                      onChange={() => setVisibility("free")}
                    />
                    <span>Free post</span>
                  </label>
                  <label className="flex items-center gap-2 rounded-xl border px-3 py-2 cursor-pointer text-sm">
                    <input
                      type="radio"
                      name="visibility"
                      checked={visibility === "ppv"}
                      onChange={() => setVisibility("ppv")}
                    />
                    <span>Pay-per-view (PPV)</span>
                  </label>
                </div>

                {visibility === "ppv" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      PPV price (USD)
                    </label>
                    <input
                      type="number"
                      min={1}
                      step={0.01}
                      className="mt-1 w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-brand-400"
                      value={price}
                      onChange={(e) => setPrice(e.target.value)}
                    />
                    <p className="mt-1 text-xs text-gray-500">
                      Fans will pay this to unlock the post.
                    </p>
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between">
                <p className="text-xs text-gray-500">
                  This MVP saves your text, price, and media file. Later we’ll
                  add scheduling, drafts, and bundles.
                </p>
                <button
                  type="submit"
                  disabled={!canSubmit}
                  className={classNames(
                    "rounded-2xl px-4 py-2 text-xs font-semibold",
                    canSubmit
                      ? "bg-brand-600 text-white hover:bg-brand-700"
                      : "bg-gray-300 text-gray-600 cursor-not-allowed"
                  )}
                >
                  {submitting ? "Posting…" : "Post"}
                </button>
              </div>
            </form>
          </div>

          {/* Posts list + edit */}
          <div className="rounded-2xl bg-white border border-gray-100 p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-800">
                Your posts ({totalPosts})
              </h2>
              <p className="text-[11px] text-gray-500">
                Fans see these on your public profile.
              </p>
            </div>

            {posts.length === 0 ? (
              <p className="text-sm text-gray-500">
                You haven&apos;t posted anything yet. Create your first post
                above.
              </p>
            ) : (
              <div className="space-y-3 max-h-80 overflow-auto pr-1">
                {posts.map((post) => {
                  const isPPV = post.visibility === "ppv";
                  const hasMedia = !!post.mediaFilename;
                  const isEditing = editingPostId === post.id;
                  const likeCount =
                    typeof post.likes === "number" ? post.likes : 0;

                  return (
                    <div
                      key={post.id}
                      className="rounded-xl border border-gray-100 px-3 py-2.5"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-semibold text-gray-900 truncate max-w-[14rem]">
                              {post.title || "Untitled post"}
                            </p>
                            {hasMedia && (
                              <span className="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">
                                Media
                              </span>
                            )}
                          </div>
                          {post.createdAt && (
                            <p className="mt-0.5 text-[11px] text-gray-500">
                              {new Date(post.createdAt).toLocaleString()}
                            </p>
                          )}

                          {/* NEW: likes row */}
                          <p className="mt-0.5 text-[11px] text-gray-500 flex items-center gap-1">
                            <span
                              className={
                                likeCount > 0
                                  ? "text-rose-500"
                                  : "text-gray-400"
                              }
                            >
                              ♥
                            </span>
                            <span>{likeCount}</span>
                            <span>likes</span>
                          </p>

                          {post.description && !isEditing && (
                            <p className="mt-1 text-xs text-gray-600 line-clamp-2">
                              {post.description}
                            </p>
                          )}
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          <span
                            className={classNames(
                              "inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium",
                              isPPV
                                ? "bg-amber-50 text-amber-700 border border-amber-100"
                                : "bg-emerald-50 text-emerald-700 border border-emerald-100"
                            )}
                          >
                            {isPPV ? "PPV" : "Free"}
                          </span>
                          {isPPV &&
                            typeof post.price === "number" &&
                            !isEditing && (
                              <span className="text-xs font-semibold text-gray-800">
                                ${post.price.toFixed(2)}
                              </span>
                            )}

                          {!isEditing && (
                            <div className="flex flex-col items-end gap-1">
                              <button
                                type="button"
                                onClick={() => handleStartEditPost(post)}
                                className="mt-1 text-[11px] text-brand-600 hover:text-brand-700"
                              >
                                Edit
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDeletePost(post.id)}
                                className="text-[11px] text-red-600 hover:text-red-700"
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </div>
                      </div>

                      {/* Inline edit form for this post */}
                      {isEditing && (
                        <form
                          onSubmit={handleSavePostEdit}
                          className="mt-3 border-t border-gray-100 pt-2 space-y-2"
                        >
                          {editError && (
                            <p className="text-[11px] text-red-600">
                              {editError}
                            </p>
                          )}
                          <div className="grid sm:grid-cols-2 gap-2">
                            <div>
                              <label className="block text-xs font-medium text-gray-700">
                                Title
                              </label>
                              <input
                                className="mt-1 w-full rounded-xl border px-2 py-1.5 text-xs outline-none focus:ring-2 focus:ring-brand-400"
                                value={editTitle}
                                onChange={(e) => setEditTitle(e.target.value)}
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-medium text-gray-700">
                                Visibility
                              </label>
                              <div className="mt-1 flex gap-2">
                                <label className="flex items-center gap-1 rounded-xl border px-2 py-1 cursor-pointer text-[11px]">
                                  <input
                                    type="radio"
                                    name={`edit-vis-${post.id}`}
                                    checked={editVisibility === "free"}
                                    onChange={() => setEditVisibility("free")}
                                  />
                                  <span>Free</span>
                                </label>
                                <label className="flex items-center gap-1 rounded-xl border px-2 py-1 cursor-pointer text-[11px]">
                                  <input
                                    type="radio"
                                    name={`edit-vis-${post.id}`}
                                    checked={editVisibility === "ppv"}
                                    onChange={() => setEditVisibility("ppv")}
                                  />
                                  <span>PPV</span>
                                </label>
                              </div>
                            </div>
                          </div>

                          {editVisibility === "ppv" && (
                            <div className="grid sm:grid-cols-[1fr,1fr] gap-2">
                              <div>
                                <label className="block text-xs font-medium text-gray-700">
                                  PPV price (USD)
                                </label>
                                <input
                                  type="number"
                                  min={1}
                                  step={0.01}
                                  className="mt-1 w-full rounded-xl border px-2 py-1.5 text-xs outline-none focus:ring-2 focus:ring-brand-400"
                                  value={editPrice}
                                  onChange={(e) => setEditPrice(e.target.value)}
                                />
                              </div>
                            </div>
                          )}

                          <div>
                            <label className="block text-xs font-medium text-gray-700">
                              Description
                            </label>
                            <textarea
                              className="mt-1 w-full rounded-xl border px-2 py-1.5 text-xs outline-none focus:ring-2 focus:ring-brand-400"
                              rows={2}
                              value={editDescription}
                              onChange={(e) =>
                                setEditDescription(e.target.value)
                              }
                            />
                          </div>

                          <div className="flex items-center justify-end gap-2">
                            <button
                              type="button"
                              onClick={handleCancelEditPost}
                              className="text-[11px] text-gray-500 hover:text-gray-700"
                            >
                              Cancel
                            </button>
                            <button
                              type="submit"
                              disabled={editSaving}
                              className={classNames(
                                "rounded-xl px-3 py-1.5 text-[11px] font-semibold",
                                editSaving
                                  ? "bg-gray-300 text-gray-600 cursor-not-allowed"
                                  : "bg-brand-600 text-white hover:bg-brand-700"
                              )}
                            >
                              {editSaving ? "Saving…" : "Save changes"}
                            </button>
                          </div>
                        </form>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </section>

        {/* RIGHT: overview + future tools */}
        <aside className="space-y-6">
          {/* Overview card */}
          <div className="rounded-2xl bg-white border border-gray-100 p-5 shadow-sm">
            <h2 className="text-sm font-semibold text-gray-800 mb-3">
              Overview
            </h2>
            <div className="grid grid-cols-3 gap-3 text-center mb-4">
              <div className="rounded-xl bg-gray-50 p-3">
                <div className="text-[11px] text-gray-500">Total posts</div>
                <div className="mt-1 text-lg font-bold">{totalPosts}</div>
              </div>
              <div className="rounded-xl bg-gray-50 p-3">
                <div className="text-[11px] text-gray-500">Free</div>
                <div className="mt-1 text-lg font-bold">{freeCount}</div>
              </div>
              <div className="rounded-xl bg-gray-50 p-3">
                <div className="text-[11px] text-gray-500">PPV</div>
                <div className="mt-1 text-lg font-bold">{ppvCount}</div>
              </div>
            </div>

            <div className="rounded-xl bg-gray-50 p-3 text-left">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-gray-500">
                  Month-to-date earnings
                </span>
                <span className="text-xs font-semibold text-gray-900">
                  {earningsLoading
                    ? "Calculating…"
                    : `${earningsCurrency} ${monthToDate.toFixed(2)}`}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-[11px] text-gray-500">
                  Last 30 days (MVP)
                </span>
                <span className="text-xs font-medium text-gray-800">
                  {earningsCurrency} {last30.toFixed(2)}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between">
                <span className="text-[11px] text-gray-500">Lifetime</span>
                <span className="text-xs font-medium text-gray-800">
                  {earningsCurrency} {lifetime.toFixed(2)}
                </span>
              </div>

              {earnings && (
                <div className="mt-3 border-t border-gray-200 pt-2">
                  <p className="text-[11px] text-gray-500 mb-1">
                    Breakdown (MVP, all-time)
                  </p>
                  <p className="text-[11px] text-gray-600">
                    Subs: {earningsCurrency}{" "}
                    {earnings.sources.subscriptions.toFixed(2)} · PPV:{" "}
                    {earningsCurrency} {earnings.sources.ppv.toFixed(2)} · Tips:{" "}
                    {earningsCurrency} {earnings.sources.tips.toFixed(2)}
                  </p>
                </div>
              )}

              {/* NEW: most liked post snippet */}
              {mostLikedPost && (
                <div className="mt-3 border-t border-gray-200 pt-2">
                  <p className="text-[11px] text-gray-500 mb-1">
                    Top post by likes
                  </p>
                  <p className="text-[11px] text-gray-700 truncate">
                    “{mostLikedPost.title || "Untitled post"}” ·{" "}
                    {typeof mostLikedPost.likes === "number"
                      ? mostLikedPost.likes
                      : 0}{" "}
                    likes
                  </p>
                </div>
              )}

              {earningsError && (
                <p className="mt-2 text-[11px] text-red-600">
                  {earningsError}
                </p>
              )}

              <p className="mt-3 text-[11px] text-gray-500">
                This MVP treats all earnings as one bucket. Later we can split
                by month, active subscribers, refunds, and payout schedule.
              </p>
            </div>
          </div>

          {/* Coming soon / CRM area */}
          <div className="rounded-2xl bg-gray-900 text-white p-5 shadow-sm">
            <h2 className="text-sm font-semibold mb-2">
              Requests, tips & DMs (coming soon)
            </h2>
            <p className="text-xs text-gray-200">
              This area will become your creator CRM:
            </p>
            <ul className="mt-2 space-y-1.5 text-xs text-gray-100">
              <li>• Inbox of custom requests</li>
              <li>• Tip history with messages from fans</li>
              <li>• Mass messaging / auto-DM tools</li>
              <li>• Analytics on which posts earn the most</li>
            </ul>
            <p className="mt-3 text-[11px] text-gray-300">
              You already have tips + custom requests on your profile. We&apos;re
              now recording earnings; next step is to surface detailed
              transaction history here.
            </p>
          </div>
        </aside>
      </main>
    </div>
  );
}
