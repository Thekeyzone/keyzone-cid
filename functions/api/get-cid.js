export async function onRequestPost({ request, env }) {
  try {
    const body = await request.json().catch(() => ({}));
    const iid = String(body.id || "").trim();
    const tsToken = String(body.tsToken || "").trim();

    // 1) basic validation
    if (!iid || iid.length < 20) return json({ error: "Wrong IID." }, 400);
    if (!tsToken) return json({ error: "Please complete the captcha." }, 400);

    const TURNSTILE_SECRET = env.TURNSTILE_SECRET;
    const GETCID_TOKEN = env.GETCID_TOKEN;

    if (!TURNSTILE_SECRET) return json({ error: "TURNSTILE_SECRET missing" }, 500);
    if (!GETCID_TOKEN) return json({ error: "GETCID_TOKEN missing" }, 500);

    // 2) Verify Turnstile
    const verifyRes = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET,
        response: tsToken,
      }),
    });

    const verifyData = await verifyRes.json().catch(() => ({}));
    if (!verifyData.success) return json({ error: "Captcha verification failed. Please try again." }, 403);

    // 3) Call getcid.info (TEXT response)
    const url = `https://getcid.info/api/${encodeURIComponent(iid)}/${encodeURIComponent(GETCID_TOKEN)}`;
    const apiRes = await fetch(url, { method: "GET" });

    const raw = (await apiRes.text().catch(() => "")).trim();

    // لو ماجا حتى رد
    if (!raw) return json({ error: "Empty response from getcid." }, 502);

    // 4) Success = digits only
    const isDigitsOnly = /^[0-9]+$/.test(raw);
    if (isDigitsOnly) {
      return json({ cid: raw }, 200);
    }

    // 5) Map getcid messages -> HTTP status
    const lower = raw.toLowerCase();

    // token issues
    if (lower.includes("token cannot be empty") || lower.includes("token does not exist") || lower.includes("used 5/5")) {
      return json({ error: raw }, 401);
    }

    // rate limit / locked
    if (lower.includes("reach request limit") || lower.includes("being locked") || lower.includes("blocked")) {
      return json({ error: raw }, 429);
    }

    // iid problems
    if (lower.includes("wrong iid") || lower.includes("exceeded iid") || lower.includes("need to call") || lower.includes("not legimate")) {
      return json({ error: raw }, 400);
    }

    // server busy
    if (lower.includes("server too busy") || lower.includes("server error")) {
      return json({ error: raw }, 503);
    }

    // default: treat as bad gateway from external
    return json({ error: raw }, 502);

  } catch (err) {
    return json({ error: "Server error" }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
