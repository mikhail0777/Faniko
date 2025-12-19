const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = 4000;

// Allow JSON bodies (for some endpoints)
app.use(express.json());

// Allow frontend
app.use(
  cors({
    origin: "http://localhost:5173",
  })
);

// Ensure uploads folder
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Serve uploads statically so frontend can display media
app.use("/uploads", express.static(uploadsDir));

// Multer storage (used both for KYC files and post media)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, file.fieldname + "-" + unique + ext);
  },
});

const upload = multer({ storage });
// Separate instance for clarity, but uses same storage
const mediaUpload = multer({ storage });

// In-memory "DB"
const users = []; // all user accounts (fans + creators)
const creators = [];
const posts = [];

// money-related data
const transactions = []; // tips, PPV unlocks, subscriptions
const subscriptions = []; // active subscriptions
const unlockedPosts = []; // which fan unlocked which PPV post

// ✅ Root: friendly message
app.get("/", (req, res) => {
  res.send(
    "Faniko API is running. Try GET /api/creators, POST /api/creators, or GET /api/creators/:username/posts"
  );
});

//
// AUTH ENDPOINTS (fans / normal users)
//

// ✅ Sign up a normal user (fan)
app.post("/api/auth/signup", (req, res) => {
  let { email, username, password } = req.body || {};

  email = (email || "").trim().toLowerCase();
  username = (username || "").trim().toLowerCase();
  password = (password || "").trim();

  console.log("🆕 Signup attempt:", { email, username });

  if (!email || !username || !password) {
    return res
      .status(400)
      .json({ error: "Missing email, username, or password." });
  }

  // Simple validation
  const emailOk = /.+@.+\..+/.test(email);
  if (!emailOk) {
    return res
      .status(400)
      .json({ error: "Please provide a valid email address." });
  }

  if (!/^[a-z0-9_]+$/.test(username)) {
    return res.status(400).json({
      error:
        "Username can only contain lowercase letters, numbers, and underscores.",
    });
  }

  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters long." });
  }

  // ✅ Enforce unique email and username
  const emailTaken = users.some((u) => u.email === email);
  if (emailTaken) {
    return res
      .status(409)
      .json({ error: "That email is already in use. Try logging in instead." });
  }

  const usernameTaken = users.some((u) => u.username === username);
  if (usernameTaken) {
    return res.status(409).json({
      error: "That username is already taken. Please choose another.",
    });
  }

  const user = {
    id: users.length + 1,
    email,
    username,
    password, // NOTE: plain text for now (MVP) – hash later
    role: "fan",
    emailVerified: false,
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  console.log("✅ Created user:", {
    id: user.id,
    email: user.email,
    username: user.username,
  });

  // Return a safe user object (no password)
  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
  });
});

// ✅ Simple login (MVP; plain-text password check)
app.post("/api/auth/login", (req, res) => {
  let { email, password } = req.body || {};
  email = (email || "").trim().toLowerCase();
  password = (password || "").trim();

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password." });
  }

  const user = users.find((u) => u.email === email);
  if (!user || user.password !== password) {
    return res.status(401).json({ error: "Invalid email or password ." });
  }

  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
  });
});

//
// CREATOR ENDPOINTS
//

// ✅ Create creator (with KYC files) + enforce unique username/email
app.post(
  "/api/creators",
  upload.fields([
    { name: "idFront", maxCount: 1 },
    { name: "idBack", maxCount: 1 },
    { name: "selfie", maxCount: 1 },
  ]),
  (req, res) => {
    let { displayName, username, email, accountType, price } = req.body;

    // Normalise inputs
    displayName = (displayName || "").trim();
    username = (username || "").trim().toLowerCase();
    email = (email || "").trim().toLowerCase();
    accountType = (accountType || "").trim();

    console.log("🔔 New creator application:", {
      displayName,
      username,
      email,
      accountType,
      price,
    });

    // Basic required fields
    if (!displayName || !username || !email || !accountType) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Enforce allowed account types
    if (!["free", "subscription"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type" });
    }

    // ✅ UNIQUE USERNAME CHECK (case-insensitive)
    const usernameTaken = creators.some(
      (c) => c.username && c.username.toLowerCase() === username
    );
    if (usernameTaken) {
      return res
        .status(409)
        .json({ error: "That creator username is already taken." });
    }

    // ✅ UNIQUE EMAIL CHECK (for creator accounts)
    const emailTaken = creators.some(
      (c) => c.email && c.email.toLowerCase() === email
    );
    if (emailTaken) {
      return res.status(409).json({
        error:
          "This email is already linked to a creator account. Try logging in instead.",
      });
    }

    const priceNumber =
      accountType === "subscription" ? Number(price) || null : null;

    const record = {
      id: creators.length + 1,
      displayName,
      username,
      email,
      accountType,
      price: priceNumber,
      idFrontPath: req.files.idFront?.[0]?.filename || null,
      idBackPath: req.files.idBack?.[0]?.filename || null,
      selfiePath: req.files.selfie?.[0]?.filename || null,
      createdAt: new Date().toISOString(),
      status: "pending",
    };

    creators.push(record);
    console.log("✅ Saved creator:", record);

    // 🔼 Upgrade matching user (if exists) to creator role
    const existingUser = users.find((u) => u.email === email);
    if (existingUser) {
      existingUser.role = "creator";
      console.log("🔼 Upgraded user to creator:", {
        id: existingUser.id,
        email: existingUser.email,
        username: existingUser.username,
      });
    }

    res.json({
      success: true,
      creatorId: record.id,
    });
  }
);

// ✅ List all creators (for Explore)
app.get("/api/creators", (req, res) => {
  res.json(creators);
});

// ✅ Get one creator by username
app.get("/api/creators/:username", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  res.json(creator);
});

// ✅ UPDATE creator profile (accountType, price, displayName)
app.patch("/api/creators/:username", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const { displayName, accountType, price } = req.body || {};

  if (displayName !== undefined) {
    const cleanName = String(displayName).trim();
    if (cleanName) {
      creator.displayName = cleanName;
    }
  }

  if (accountType !== undefined) {
    if (!["free", "subscription"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type" });
    }
    creator.accountType = accountType;

    if (accountType === "subscription") {
      // if switching to subscription, set or update price
      creator.price = Number(price) || creator.price || 0;
    } else {
      // switching to free -> no subscription price
      creator.price = null;
    }
  } else if (price !== undefined && creator.accountType === "subscription") {
    // Only update price if they are already subscription-type
    creator.price = Number(price) || 0;
  }

  console.log("✏️ Updated creator profile:", creator);

  res.json({
    success: true,
    creator,
  });
});

// ✅ Get posts for a creator by username (ensure likes + likedBy exist)
app.get("/api/creators/:username/posts", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const creatorPosts = posts
    .filter((p) => p.username && p.username.toLowerCase() === username)
    .map((p) => {
      if (typeof p.likes !== "number") p.likes = 0;
      if (!Array.isArray(p.likedBy)) p.likedBy = [];
      return p;
    });

  res.json(creatorPosts);
});

// ✅ Create a post for a creator (with optional media: image or video)
app.post(
  "/api/creators/:username/posts",
  mediaUpload.single("media"), // "media" is the file field name from frontend
  (req, res) => {
    const username = req.params.username.toLowerCase();
    const creator = creators.find(
      (c) => c.username && c.username.toLowerCase() === username
    );

    if (!creator) {
      return res.status(404).json({ error: "Creator not found" });
    }

    const { title, visibility, price, description } = req.body;

    if (!title || !visibility) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (!["free", "ppv"].includes(visibility)) {
      return res.status(400).json({ error: "Invalid visibility" });
    }

    const record = {
      id: posts.length + 1,
      creatorId: creator.id,
      username: creator.username,
      title: title.trim(),
      visibility,
      price: visibility === "ppv" ? Number(price) || 0 : null,
      description: description || "",
      createdAt: new Date().toISOString(),

      // media fields
      mediaFilename: req.file ? req.file.filename : null,
      mediaMime: req.file ? req.file.mimetype : null,

      // likes (MVP, in-memory)
      likes: 0,
      likedBy: [],
    };

    posts.push(record);

    console.log("🆕 New post:", record);

    res.json({ success: true, post: record });
  }
);

// ✅ EDIT a creator post (change price, visibility, description, title)
app.patch("/api/creators/:username/posts/:postId", (req, res) => {
  const username = req.params.username.toLowerCase();
  const postId = Number(req.params.postId);

  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );
  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const post = posts.find(
    (p) =>
      p.id === postId &&
      p.username &&
      p.username.toLowerCase() === username
  );
  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }

  const { title, visibility, price, description } = req.body || {};

  if (title !== undefined) {
    const cleanTitle = String(title).trim();
    if (cleanTitle) {
      post.title = cleanTitle;
    }
  }

  if (visibility !== undefined) {
    if (!["free", "ppv"].includes(visibility)) {
      return res.status(400).json({ error: "Invalid visibility" });
    }
    post.visibility = visibility;

    if (visibility === "ppv") {
      post.price = Number(price) || post.price || 0;
    } else {
      post.price = null;
    }
  } else if (price !== undefined && post.visibility === "ppv") {
    post.price = Number(price) || 0;
  }

  if (description !== undefined) {
    post.description = String(description);
  }

  console.log("✏️ Updated post:", post);

  res.json({ success: true, post });
});

// ✅ DELETE a creator post (no archive – hard delete of content)
app.delete("/api/creators/:username/posts/:postId", (req, res) => {
  const username = req.params.username.toLowerCase();
  const postId = Number(req.params.postId);

  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );
  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const index = posts.findIndex(
    (p) =>
      p.id === postId &&
      p.username &&
      p.username.toLowerCase() === username
  );

  if (index === -1) {
    return res.status(404).json({ error: "Post not found" });
  }

  const [deletedPost] = posts.splice(index, 1);

  // Clean up unlockedPosts for this post (so no dangling unlock entries)
  for (let i = unlockedPosts.length - 1; i >= 0; i--) {
    const u = unlockedPosts[i];
    if (
      u.postId === postId &&
      u.creatorUsername &&
      u.creatorUsername.toLowerCase() === username
    ) {
      unlockedPosts.splice(i, 1);
    }
  }

  console.log("🗑️ Deleted post:", deletedPost);

  // We do NOT remove transactions, so earnings stats still count
  // what fans already paid for, even if the post is gone.
  res.json({ success: true });
});

//
// PAYMENTS / TRANSACTIONS (MVP – no real Stripe yet)
//

// ✅ 1) TIP endpoint
// Body: { amount, message?, fanUsername?, fanEmail?, postId? }
app.post("/api/creators/:username/tips", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  let { amount, message, fanUsername, fanEmail, postId } = req.body || {};
  const amountNum = Number(amount);

  if (!amount || Number.isNaN(amountNum) || amountNum <= 0) {
    return res
      .status(400)
      .json({ error: "Please provide a valid tip amount." });
  }

  const txn = {
    id: transactions.length + 1,
    type: "tip",
    creatorUsername: creator.username,
    fanUsername: (fanUsername || "").toString() || "anonymous",
    fanEmail: (fanEmail || "").toString() || null,
    amount: amountNum,
    currency: "USD",
    message: (message || "").toString().slice(0, 500),
    postId: postId ? Number(postId) : null,
    createdAt: new Date().toISOString(),
  };

  transactions.push(txn);
  console.log("💸 New tip:", txn);

  res.json({
    success: true,
    transaction: txn,
  });
});

// ✅ 2) PPV unlock endpoint
// Body: { fanUsername?, fanEmail? }
app.post("/api/creators/:username/posts/:postId/unlock", (req, res) => {
  const username = req.params.username.toLowerCase();
  const postId = Number(req.params.postId);

  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );
  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const post = posts.find(
    (p) => p.id === postId && p.username === creator.username
  );
  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }

  if (
    post.visibility !== "ppv" ||
    typeof post.price !== "number" ||
    post.price <= 0
  ) {
    return res.status(400).json({ error: "This post is not a paid PPV post." });
  }

  let { fanUsername, fanEmail } = req.body || {};
  fanUsername = (fanUsername || "").toString();
  fanEmail = (fanEmail || "").toString();

  // Check if already unlocked for this fan
  const already = unlockedPosts.find(
    (u) =>
      u.postId === postId &&
      u.creatorUsername.toLowerCase() === username &&
      u.fanUsername === fanUsername
  );

  if (already) {
    return res.json({
      success: true,
      alreadyUnlocked: true,
      unlockedPostId: post.id,
    });
  }

  const txn = {
    id: transactions.length + 1,
    type: "ppv_unlock",
    creatorUsername: creator.username,
    fanUsername: fanUsername || "anonymous",
    fanEmail: fanEmail || null,
    amount: post.price,
    currency: "USD",
    postId: post.id,
    createdAt: new Date().toISOString(),
  };

  transactions.push(txn);
  unlockedPosts.push({
    creatorUsername: creator.username,
    fanUsername: fanUsername || "anonymous",
    postId: post.id,
    createdAt: new Date().toISOString(),
  });

  console.log("🔓 PPV unlocked:", { txn });

  res.json({
    success: true,
    unlockedPostId: post.id,
    transaction: txn,
  });
});

// ✅ 2b) Like / unlike a post
// Body: { fanUsername }
app.post("/api/creators/:username/posts/:postId/like", (req, res) => {
  const username = req.params.username.toLowerCase();
  const postId = Number(req.params.postId);

  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );
  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const post = posts.find(
    (p) =>
      p.id === postId &&
      p.username &&
      p.username.toLowerCase() === creator.username.toLowerCase()
  );
  if (!post) {
    return res.status(404).json({ error: "Post not found" });
  }

  let { fanUsername } = req.body || {};
  fanUsername = (fanUsername || "").toString().trim();

  if (!fanUsername) {
    return res.status(400).json({ error: "Missing fan username." });
  }

  if (!Array.isArray(post.likedBy)) {
    post.likedBy = [];
  }

  // case-insensitive match for usernames
  const existingIndex = post.likedBy.findIndex(
    (name) => String(name).toLowerCase() === fanUsername.toLowerCase()
  );

  let likedByMe;
  if (existingIndex === -1) {
    // like
    post.likedBy.push(fanUsername);
    likedByMe = true;
  } else {
    // unlike
    post.likedBy.splice(existingIndex, 1);
    likedByMe = false;
  }

  post.likes = post.likedBy.length;

  console.log("❤️ Like toggle:", {
    postId: post.id,
    fanUsername,
    likes: post.likes,
    likedByMe,
  });

  res.json({
    success: true,
    postId: post.id,
    likes: post.likes,
    likedByMe,
  });
});

// ✅ 3) Subscription endpoint
// Body: { fanUsername?, fanEmail? }
app.post("/api/creators/:username/subscribe", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  if (creator.accountType !== "subscription") {
    return res.status(400).json({
      error: "This creator does not have a subscription plan.",
    });
  }

  if (typeof creator.price !== "number" || creator.price <= 0) {
    return res.status(400).json({
      error: "This creator's subscription price is not configured.",
    });
  }

  let { fanUsername, fanEmail } = req.body || {};
  fanUsername = (fanUsername || "").toString();
  fanEmail = (fanEmail || "").toString();

  // Check if already subscribed
  const existing = subscriptions.find(
    (s) =>
      s.creatorUsername.toLowerCase() === username &&
      s.fanUsername === fanUsername
  );

  if (existing) {
    return res.json({
      success: true,
      alreadySubscribed: true,
      subscription: existing,
    });
  }

  const subscription = {
    id: subscriptions.length + 1,
    creatorUsername: creator.username,
    fanUsername: fanUsername || "anonymous",
    fanEmail: fanEmail || null,
    price: creator.price,
    currency: "USD",
    status: "active",
    createdAt: new Date().toISOString(),
  };

  subscriptions.push(subscription);

  const txn = {
    id: transactions.length + 1,
    type: "subscription",
    creatorUsername: creator.username,
    fanUsername: fanUsername || "anonymous",
    fanEmail: fanEmail || null,
    amount: creator.price,
    currency: "USD",
    postId: null,
    createdAt: new Date().toISOString(),
  };

  transactions.push(txn);

  console.log("🧾 New subscription + txn:", { subscription, txn });

  res.json({
    success: true,
    subscription,
    transaction: txn,
  });
});

// ✅ 4) Earnings summary for a creator
app.get("/api/creators/:username/earnings", (req, res) => {
  const username = req.params.username.toLowerCase();
  const creator = creators.find(
    (c) => c.username && c.username.toLowerCase() === username
  );

  if (!creator) {
    return res.status(404).json({ error: "Creator not found" });
  }

  const creatorTx = transactions.filter(
    (t) => t.creatorUsername && t.creatorUsername.toLowerCase() === username
  );

  const totalTips = creatorTx
    .filter((t) => t.type === "tip")
    .reduce((sum, t) => sum + (t.amount || 0), 0);

  const totalPpv = creatorTx
    .filter((t) => t.type === "ppv_unlock")
    .reduce((sum, t) => sum + (t.amount || 0), 0);

  const totalSubs = creatorTx
    .filter((t) => t.type === "subscription")
    .reduce((sum, t) => sum + (t.amount || 0), 0);

  const total = totalTips + totalPpv + totalSubs;

  res.json({
    creator: creator.username,
    totals: {
      tips: totalTips,
      ppv: totalPpv,
      subscriptions: totalSubs,
      allTime: total,
    },
    transactions: creatorTx,
  });
});

app.listen(PORT, () => {
  console.log(`Faniko backend running on http://localhost:${PORT}`);
});

