const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

console.log("=== DEBUG: BACKEND FILE LOADED ===");
console.log("RUNNING BACKEND FROM:", __dirname);
console.log("DATA FILE PATH:", path.join(__dirname, "data.json"));

const app = express();
const PORT = 4000;

// Allow JSON bodies
app.use(express.json());

// Allow frontend (and auth header)
app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
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
const mediaUpload = multer({ storage });

// In-memory "DB"
const users = []; // fans + creators
const creators = [];
const posts = [];
const transactions = [];
const subscriptions = [];
const unlockedPosts = [];
const messages = [];

// Data persistence configuration
const DATA_FILE = path.join(__dirname, "data.json");
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_TO_RANDOM_SECRET";

/**
 * Load persisted data from disk into memory.
 */
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, "utf-8");
      const parsed = JSON.parse(raw);

      users.splice(0, users.length, ...(parsed.users || []));
      creators.splice(0, creators.length, ...(parsed.creators || []));
      posts.splice(0, posts.length, ...(parsed.posts || []));
      transactions.splice(0, transactions.length, ...(parsed.transactions || []));
      subscriptions.splice(0, subscriptions.length, ...(parsed.subscriptions || []));
      unlockedPosts.splice(0, unlockedPosts.length, ...(parsed.unlockedPosts || []));
      messages.splice(0, messages.length, ...(parsed.messages || []));
    }
  } catch (err) {
    console.error("Failed to load data:", err);
  }
}

/**
 * Persist current in-memory data to disk.
 */
function saveData() {
  try {
    const toSave = {
      users,
      creators,
      posts,
      transactions,
      subscriptions,
      unlockedPosts,
      messages,
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(toSave, null, 2));
  } catch (err) {
    console.error("Failed to save data:", err);
  }
}

// Attempt to load existing data at startup
loadData();

/**
 * Strict auth: requires Bearer token
 */
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "Missing authentication token." });
  }

  const token = authHeader.replace("Bearer ", "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = users.find((u) => u.id === decoded.userId);
    if (!currentUser) {
      return res.status(401).json({ error: "Invalid user." });
    }
    req.user = currentUser;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

/**
 * Optional auth: if token exists, attach req.user; otherwise guest
 */
function optionalAuthenticate(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader) return next();

  const token = authHeader.replace("Bearer ", "");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const currentUser = users.find((u) => u.id === decoded.userId);
    if (currentUser) req.user = currentUser;
  } catch (e) {
    // ignore invalid token -> treat as guest
  }
  next();
}

/**
 * Helper: Normalize username safely
 */
function normUsername(u) {
  return String(u || "").trim().toLowerCase();
}

/**
 * Helper: Find creator by username (case-insensitive)
 */
function findCreatorByUsername(username) {
  const u = normUsername(username);
  return creators.find((c) => normUsername(c.username) === u);
}

// ✅ Root
app.get("/", (req, res) => {
  res.send(
    "Faniko API is running. Try GET /api/creators, POST /api/creators, or GET /api/creators/:username/posts"
  );
});

//
// AUTH
//

app.post("/api/auth/signup", (req, res) => {
  let { email, username, password } = req.body || {};

  email = (email || "").trim().toLowerCase();
  username = (username || "").trim().toLowerCase();
  password = (password || "").trim();

  if (!email || !username || !password) {
    return res.status(400).json({ error: "Missing email, username, or password." });
  }

  const emailOk = /.+@.+\..+/.test(email);
  if (!emailOk) {
    return res.status(400).json({ error: "Please provide a valid email address." });
  }

  if (!/^[a-z0-9_]+$/.test(username)) {
    return res.status(400).json({
      error: "Username can only contain lowercase letters, numbers, and underscores.",
    });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long." });
  }

  const emailTaken = users.some((u) => u.email === email);
  if (emailTaken) {
    return res.status(409).json({ error: "That email is already in use. Try logging in instead." });
  }

  const usernameTaken = users.some((u) => u.username === username);
  if (usernameTaken) {
    return res.status(409).json({ error: "That username is already taken. Please choose another." });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const verificationToken = crypto.randomBytes(32).toString("hex");

  const user = {
    id: users.length + 1,
    email,
    username,
    password: passwordHash,
    role: "fan",
    emailVerified: false,
    verificationToken,
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  saveData();

  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
    message:
      "Signup successful. Please verify your email by visiting /api/auth/verify-email?token=<token> with the token provided.",
    verificationToken,
  });
});

app.post("/api/auth/login", (req, res) => {
  let { email, password } = req.body || {};
  email = (email || "").trim().toLowerCase();
  password = (password || "").trim();

  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password." });
  }

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  if (!user.emailVerified) {
    return res.status(401).json({ error: "Email not verified. Please verify your email." });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1d" });

  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
    token,
  });
});

app.get("/api/auth/verify-email", (req, res) => {
  const { token } = req.query || {};
  if (!token) return res.status(400).json({ error: "Missing verification token." });

  const user = users.find((u) => u.verificationToken === token);
  if (!user) return res.status(400).json({ error: "Invalid verification token." });

  user.emailVerified = true;
  user.verificationToken = null;
  saveData();

  res.json({ success: true, message: "Email successfully verified." });
});

//
// CREATORS
//

app.post(
  "/api/creators",
  upload.fields([
    { name: "idFront", maxCount: 1 },
    { name: "idBack", maxCount: 1 },
    { name: "selfie", maxCount: 1 },
  ]),
  (req, res) => {
    let { displayName, username, email, accountType, price } = req.body;

    displayName = (displayName || "").trim();
    username = (username || "").trim().toLowerCase();
    email = (email || "").trim().toLowerCase();
    accountType = (accountType || "").trim();

    if (!displayName || !username || !email || !accountType) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (!["free", "subscription"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type" });
    }

    const usernameTaken = creators.some((c) => normUsername(c.username) === username);
    if (usernameTaken) {
      return res.status(409).json({ error: "That creator username is already taken." });
    }

    const emailTaken = creators.some((c) => String(c.email || "").toLowerCase() === email);
    if (emailTaken) {
      return res.status(409).json({
        error: "This email is already linked to a creator account. Try logging in instead.",
      });
    }

    const priceNumber = accountType === "subscription" ? Number(price) || 0 : null;

    const record = {
      id: creators.length + 1,
      displayName,
      username,
      email,
      accountType,
      price: priceNumber,
      idFrontPath: req.files?.idFront?.[0]?.filename || null,
      idBackPath: req.files?.idBack?.[0]?.filename || null,
      selfiePath: req.files?.selfie?.[0]?.filename || null,
      createdAt: new Date().toISOString(),
      status: "pending",
    };

    creators.push(record);

    const existingUser = users.find((u) => u.email === email);
    if (existingUser) existingUser.role = "creator";

    saveData();
    res.json({ success: true, creatorId: record.id });
  }
);

app.get("/api/creators", (req, res) => {
  res.json(creators);
});

app.get("/api/creators/:username", (req, res) => {
  const creator = findCreatorByUsername(req.params.username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });
  res.json(creator);
});

app.patch("/api/creators/:username", (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const { displayName, accountType, price } = req.body || {};

  if (displayName !== undefined) {
    const cleanName = String(displayName).trim();
    if (cleanName) creator.displayName = cleanName;
  }

  if (accountType !== undefined) {
    if (!["free", "subscription"].includes(accountType)) {
      return res.status(400).json({ error: "Invalid account type" });
    }
    creator.accountType = accountType;
    if (accountType === "subscription") creator.price = Number(price) || creator.price || 0;
    else creator.price = null;
  } else if (price !== undefined && creator.accountType === "subscription") {
    creator.price = Number(price) || 0;
  }

  saveData();
  res.json({ success: true, creator });
});

//
// POSTS (with locked flag)
//
app.get("/api/creators/:username/posts", optionalAuthenticate, (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  // viewer identity
  const viewerUser = req.user || null;

  // If creator is viewing their own profile, do not lock anything.
  const viewerIsOwnerCreator =
    viewerUser &&
    viewerUser.role === "creator" &&
    normUsername(viewerUser.username) === username;

  // Fan username (prefer token, fallback query)
  let fanUsername = null;
  if (!viewerIsOwnerCreator) {
    if (viewerUser) {
      fanUsername = normUsername(viewerUser.username);
    } else if (req.query.fanUsername) {
      fanUsername = normUsername(req.query.fanUsername);
    }
  }

  const creatorPosts = posts
    .filter((p) => normUsername(p.username) === username)
    .map((p) => {
      if (typeof p.likes !== "number") p.likes = 0;
      if (!Array.isArray(p.likedBy)) p.likedBy = [];

      let locked = false;

      if (!viewerIsOwnerCreator) {
        // Subscription gating for non-free content
        if (creator.accountType === "subscription") {
          if (p.visibility !== "free") {
            if (!fanUsername) {
              locked = true;
            } else {
              const sub = subscriptions.find(
                (s) =>
                  normUsername(s.creatorUsername) === username &&
                  normUsername(s.fanUsername) === fanUsername &&
                  s.status === "active" &&
                  (!s.expiresAt || new Date(s.expiresAt) > new Date())
              );
              if (!sub) locked = true;
            }
          }
        }

        // PPV gating (always needs unlock)
        if (p.visibility === "ppv") {
          let unlocked = false;
          if (fanUsername) {
            const unlockedEntry = unlockedPosts.find(
              (u) =>
                u.postId === p.id &&
                normUsername(u.creatorUsername) === username &&
                normUsername(u.fanUsername) === fanUsername
            );
            if (unlockedEntry) unlocked = true;
          }
          if (!unlocked) locked = true;
        }
      }

      const out = { ...p, locked };
      if (locked) {
        out.mediaFilename = null;
        out.description = "";
      }
      return out;
    });

  res.json(creatorPosts);
});

app.post("/api/creators/:username/posts", mediaUpload.single("media"), (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const { title, visibility, price, description } = req.body;
  if (!title || !visibility) return res.status(400).json({ error: "Missing required fields" });
  if (!["free", "ppv"].includes(visibility)) return res.status(400).json({ error: "Invalid visibility" });

  const record = {
    id: posts.length + 1,
    creatorId: creator.id,
    username: creator.username,
    title: String(title).trim(),
    visibility,
    price: visibility === "ppv" ? Number(price) || 0 : null,
    description: description ? String(description) : "",
    createdAt: new Date().toISOString(),
    mediaFilename: req.file ? req.file.filename : null,
    mediaMime: req.file ? req.file.mimetype : null,
    likes: 0,
    likedBy: [],
  };

  posts.push(record);
  saveData();
  res.json({ success: true, post: record });
});

app.patch("/api/creators/:username/posts/:postId", (req, res) => {
  const username = normUsername(req.params.username);
  const postId = Number(req.params.postId);

  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const post = posts.find((p) => p.id === postId && normUsername(p.username) === username);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const { title, visibility, price, description } = req.body || {};

  if (title !== undefined) {
    const cleanTitle = String(title).trim();
    if (cleanTitle) post.title = cleanTitle;
  }

  if (visibility !== undefined) {
    if (!["free", "ppv"].includes(visibility)) return res.status(400).json({ error: "Invalid visibility" });
    post.visibility = visibility;
    post.price = visibility === "ppv" ? Number(price) || post.price || 0 : null;
  } else if (price !== undefined && post.visibility === "ppv") {
    post.price = Number(price) || 0;
  }

  if (description !== undefined) post.description = String(description);

  saveData();
  res.json({ success: true, post });
});

app.delete("/api/creators/:username/posts/:postId", (req, res) => {
  const username = normUsername(req.params.username);
  const postId = Number(req.params.postId);

  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const index = posts.findIndex((p) => p.id === postId && normUsername(p.username) === username);
  if (index === -1) return res.status(404).json({ error: "Post not found" });

  posts.splice(index, 1);

  // Remove unlock records for this post
  for (let i = unlockedPosts.length - 1; i >= 0; i--) {
    const u = unlockedPosts[i];
    if (u.postId === postId && normUsername(u.creatorUsername) === username) {
      unlockedPosts.splice(i, 1);
    }
  }

  saveData();
  res.json({ success: true });
});

//
// TRANSACTIONS (fixed identity handling)
//

// TIP
app.post("/api/creators/:username/tips", optionalAuthenticate, (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  let { amount, message, fanUsername, fanEmail, postId } = req.body || {};

  // ✅ prefer authenticated identity
  if (req.user) {
    fanUsername = req.user.username;
    fanEmail = req.user.email;
  }

  const amountNum = Number(amount);
  if (!amount || Number.isNaN(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: "Please provide a valid tip amount." });
  }

  const txn = {
    id: transactions.length + 1,
    type: "tip",
    creatorUsername: creator.username,
    fanUsername: String(fanUsername || "").trim() || "anonymous",
    fanEmail: String(fanEmail || "").trim() || null,
    amount: amountNum,
    currency: "USD",
    message: (message || "").toString().slice(0, 500),
    postId: postId ? Number(postId) : null,
    createdAt: new Date().toISOString(),
  };

  transactions.push(txn);
  saveData();
  res.json({ success: true, transaction: txn });
});

// UNLOCK PPV
app.post("/api/creators/:username/posts/:postId/unlock", optionalAuthenticate, (req, res) => {
  const username = normUsername(req.params.username);
  const postId = Number(req.params.postId);

  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const post = posts.find((p) => p.id === postId && normUsername(p.username) === username);
  if (!post) return res.status(404).json({ error: "Post not found" });

  if (post.visibility !== "ppv" || typeof post.price !== "number" || post.price <= 0) {
    return res.status(400).json({ error: "This post is not a paid PPV post." });
  }

  let { fanUsername, fanEmail } = req.body || {};

  // ✅ prefer authenticated identity
  if (req.user) {
    fanUsername = req.user.username;
    fanEmail = req.user.email;
  }

  fanUsername = String(fanUsername || "").trim();
  fanEmail = String(fanEmail || "").trim();

  if (!fanUsername) {
    return res.status(400).json({ error: "Missing fan identity (login required or provide fanUsername)." });
  }

  const already = unlockedPosts.find(
    (u) =>
      u.postId === postId &&
      normUsername(u.creatorUsername) === username &&
      normUsername(u.fanUsername) === normUsername(fanUsername)
  );

  if (already) {
    return res.json({ success: true, alreadyUnlocked: true, unlockedPostId: post.id });
  }

  const txn = {
    id: transactions.length + 1,
    type: "ppv_unlock",
    creatorUsername: creator.username,
    fanUsername,
    fanEmail: fanEmail || null,
    amount: post.price,
    currency: "USD",
    postId: post.id,
    createdAt: new Date().toISOString(),
  };

  transactions.push(txn);
  unlockedPosts.push({
    creatorUsername: creator.username,
    fanUsername,
    postId: post.id,
    createdAt: new Date().toISOString(),
  });

  saveData();
  res.json({ success: true, unlockedPostId: post.id, transaction: txn });
});

// LIKE / UNLIKE
app.post("/api/creators/:username/posts/:postId/like", optionalAuthenticate, (req, res) => {
  const username = normUsername(req.params.username);
  const postId = Number(req.params.postId);

  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const post = posts.find((p) => p.id === postId && normUsername(p.username) === username);
  if (!post) return res.status(404).json({ error: "Post not found" });

  let { fanUsername } = req.body || {};

  // ✅ prefer authenticated identity
  if (req.user) fanUsername = req.user.username;

  fanUsername = String(fanUsername || "").trim();
  if (!fanUsername) {
    return res.status(400).json({ error: "Missing fan identity (login required or provide fanUsername)." });
  }

  if (!Array.isArray(post.likedBy)) post.likedBy = [];

  const idx = post.likedBy.findIndex((n) => normUsername(n) === normUsername(fanUsername));

  let likedByMe;
  if (idx === -1) {
    post.likedBy.push(fanUsername);
    likedByMe = true;
  } else {
    post.likedBy.splice(idx, 1);
    likedByMe = false;
  }

  post.likes = post.likedBy.length;
  saveData();

  res.json({ success: true, postId: post.id, likes: post.likes, likedByMe });
});

// SUBSCRIBE
app.post("/api/creators/:username/subscribe", optionalAuthenticate, (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  if (creator.accountType !== "subscription") {
    return res.status(400).json({ error: "This creator does not have a subscription plan." });
  }
  if (typeof creator.price !== "number" || creator.price <= 0) {
    return res.status(400).json({ error: "This creator's subscription price is not configured." });
  }

  let { fanUsername, fanEmail } = req.body || {};

  // ✅ prefer authenticated identity
  if (req.user) {
    fanUsername = req.user.username;
    fanEmail = req.user.email;
  }

  fanUsername = String(fanUsername || "").trim();
  fanEmail = String(fanEmail || "").trim();

  if (!fanUsername) {
    return res.status(400).json({ error: "Missing fan identity (login required or provide fanUsername)." });
  }

  const existing = subscriptions.find(
    (s) =>
      normUsername(s.creatorUsername) === username &&
      normUsername(s.fanUsername) === normUsername(fanUsername) &&
      s.status === "active" &&
      (!s.expiresAt || new Date(s.expiresAt) > new Date())
  );

  if (existing) {
    return res.json({ success: true, alreadySubscribed: true, subscription: existing });
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

  const subscription = {
    id: subscriptions.length + 1,
    creatorUsername: creator.username,
    fanUsername,
    fanEmail: fanEmail || null,
    price: creator.price,
    currency: "USD",
    status: "active",
    createdAt: now.toISOString(),
    expiresAt,
  };

  subscriptions.push(subscription);

  const txn = {
    id: transactions.length + 1,
    type: "subscription",
    creatorUsername: creator.username,
    fanUsername,
    fanEmail: fanEmail || null,
    amount: creator.price,
    currency: "USD",
    postId: null,
    createdAt: now.toISOString(),
  };

  transactions.push(txn);
  saveData();

  res.json({ success: true, subscription, transaction: txn });
});

// Earnings summary
app.get("/api/creators/:username/earnings", (req, res) => {
  const username = normUsername(req.params.username);
  const creator = findCreatorByUsername(username);
  if (!creator) return res.status(404).json({ error: "Creator not found" });

  const creatorTx = transactions.filter((t) => normUsername(t.creatorUsername) === username);

  const totalTips = creatorTx.filter((t) => t.type === "tip").reduce((sum, t) => sum + (t.amount || 0), 0);
  const totalPpv = creatorTx.filter((t) => t.type === "ppv_unlock").reduce((sum, t) => sum + (t.amount || 0), 0);
  const totalSubs = creatorTx.filter((t) => t.type === "subscription").reduce((sum, t) => sum + (t.amount || 0), 0);

  res.json({
    creator: creator.username,
    totals: {
      tips: totalTips,
      ppv: totalPpv,
      subscriptions: totalSubs,
      allTime: totalTips + totalPpv + totalSubs,
    },
    transactions: creatorTx,
  });
});

app.listen(PORT, () => {
  console.log(`Faniko backend running on http://localhost:${PORT}`);
});

