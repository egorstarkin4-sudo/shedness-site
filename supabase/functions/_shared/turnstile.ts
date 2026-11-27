export async function verifyTurnstile(
  token: string | undefined,
  remoteIp: string,
): Promise<{ ok: boolean; error?: string }> {
  const secret = (Deno.env.get("TURNSTILE_SECRET_KEY") ?? "").trim();
  if (!secret) {
    if (Deno.env.get("ALLOW_DEV_TURNSTILE_BYPASS") === "true") {
      return { ok: true };
    }
    return { ok: false, error: "Captcha verification is not configured" };
  }

  if (!token || token.length < 10 || token.length > 2048) {
    return { ok: false, error: "Captcha token missing or invalid" };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000);

  try {
    const form = new URLSearchParams();
    form.set("secret", secret);
    form.set("response", token.trim());
    if (remoteIp && remoteIp !== "unknown") {
      form.set("remoteip", remoteIp);
    }

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: controller.signal,
    });

    const result = (await res.json().catch(() => null)) as {
      success?: boolean;
      "error-codes"?: string[];
    } | null;

    if (!res.ok || !result) {
      console.warn("Turnstile HTTP error:", res.status, result?.["error-codes"] ?? []);
      return { ok: false, error: "Captcha provider unavailable" };
    }

    if (!result.success) {
      const codes = result["error-codes"] ?? [];
      console.warn("Turnstile verify rejected:", codes);
      if (codes.includes("invalid-input-secret")) {
        return { ok: false, error: "Turnstile secret key invalid on server" };
      }
      return { ok: false, error: "Captcha verification failed" };
    }

    return { ok: true };
  } catch (err) {
    console.warn("Turnstile fetch error:", err instanceof Error ? err.message : String(err));
    return { ok: false, error: "Captcha verification timeout" };
  } finally {
    clearTimeout(timeoutId);
  }
}
