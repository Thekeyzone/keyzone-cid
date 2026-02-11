const REQUIRED_DIGITS = 63;

export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));

    const iidRaw = String(body.id || "").trim();
    const tsToken = String(body.tsToken || "").trim();

    // digits only
    const iid = iidRaw.replace(/[^\d]/g, "");

    if (iid.length !== REQUIRED_DIGITS) {
      return json({ error: `Wrong IID. Must be ${REQUIRED_DIGITS} digits.` }, 400);
    }
    if (!tsToken) {
      return json({ error: "Please complete the captcha." }, 400);
    }

    const { TURNSTILE_SECRET, GETCID_TOKEN, CACHE } = env;

    if (!TURNSTILE_SECRET) return json({ error: "TURNSTILE_SECRET missing" }, 500);

    // إذا مازال ما عندكش GETCID_TOKEN (باش تديپلوي دابا)
    if (!GETCID_TOKEN) {
      return json(
        { error: "GETCID_TOKEN is not set yet. Please add it in Cloudflare → Settings → Variables." },
        503
      );
    }

    // ✅ Cache first (KV)
    if (CACHE) {
      const cached = await CACHE.get(iid);
      if (cached && /^[0-9]+$/.test(cached)) {
        return json({ cid: cached, cached: true }, 200);
      }
    }

    // ✅ Verify Turnstile
    const cfIP = request.headers.get("CF-Connecting-IP") || "";
    const xff = request.headers.get("x-forwarded-for") || "";
    const ip = cfIP || (xff ? xff.split(",")[0].trim() : "");

    const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET,
        response: tsToken,
        ...(ip ? { remoteip: ip } : {}),
      }),
    });

    const verifyData = await verifyRes.json().catch(() => ({}));
    if (!verifyData.success) {
      return json({ error: "Captcha verification failed. Please try again." }, 403);
    }

    // ✅ Call getcid.info (TEXT response)
    const url = `https://getcid.info/api/${encodeURIComponent(iid)}/${encodeURIComponent(GETCID_TOKEN)}`;
    const apiRes = await fetch(url, { method: "GET" });
    const raw = (await apiRes.text().catch(() => "")).trim();

    if (!raw) return json({ error: "Empty response from getcid." }, 502);

    // ✅ Success (digits only)
    if (/^[0-9]+$/.test(raw)) {
      if (CACHE) {
        await CACHE.put(iid, raw, { expirationTtl: 60 * 60 * 24 * 30 }); // 30 days
      }
      return json({ cid: raw, cached: false }, 200);
    }

    // ✅ Map getcid messages
    const lower = raw.toLowerCase();

    // token issues
    if (
      lower.includes("token cannot be empty") ||
      lower.includes("token does not exist") ||
      lower.includes("used 5/5")
    ) {
      return json({ error: raw }, 401);
    }

    // rate limit / locked
    if (
      lower.includes("reach request limit") ||
      lower.includes("being locked") ||
      lower.includes("your ip") ||
      lower.includes("locked")
    ) {
      return json({ error: raw }, 429);
    }

    // iid problems
    if (
      lower.includes("wrong iid") ||
      lower.includes("blocked iid") ||
      lower.includes("exceeded iid") ||
      lower.includes("need to call") ||
      lower.includes("not legimate") ||
      lower.includes("maybe blocked")
    ) {
      return json({ error: raw }, 400);
    }

    // server busy
    if (lower.includes("server too busy") || lower.includes("server error")) {
      return json({ error: raw }, 503);
    }

    // default
    return json({ error: raw }, 502);

  } catch (err) {
    return json({ error: "Server error" }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}
