import express from "express";
import rateLimit from "express-rate-limit";
import "dotenv/config";

const app = express();
app.use(express.json());

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;

// ✅ Rate limit: 10 requests per minute per IP
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please wait and try again." },
});

// نطبق الحماية غير على /api
app.use("/api/", limiter);

app.post("/api/get-cid", async (req, res) => {
  try {
    const { id, tsToken } = req.body || {};

    if (!id) return res.status(400).json({ error: "ID is required" });
    if (!tsToken) return res.status(400).json({ error: "Please complete the captcha." });

    if (!TURNSTILE_SECRET) {
      return res.status(500).json({ error: "TURNSTILE_SECRET is missing in .env" });
    }

    // ✅ Verify Turnstile token with Cloudflare
    const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET,
        response: tsToken,
        remoteip: req.ip,
      }),
    });

    const verifyData = await verifyRes.json();

    if (!verifyData.success) {
      return res.status(403).json({ error: "Captcha verification failed. Please try again." });
    }

    // ✅ Demo CID (until the real API is ready)
    const demoCid = `DEMO-CID-${id}-${Math.random().toString(16).slice(2, 8).toUpperCase()}`;
    return res.json({ cid: demoCid });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// serve index.html + assets (logo, privacy, terms...)
app.use(express.static("."));

app.listen(3000, () => console.log("Server running at http://localhost:3000"));
