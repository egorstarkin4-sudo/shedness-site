export async function verifyTurnstile(
  token: string | undefined,
  remoteIp: string,
): Promise<{ ok: boolean; error?: string }> {
  const secret = Deno.env.get("TURNSTILE_SECRET_KEY");
  if (!secret) {
    // Only allow bypass in explicit local development mode
    if (Deno.env.get("ALLOW_DEV_TURNSTILE_BYPASS") === "true") {
      return { ok: true };
    }
    return { ok: false, error: "Captcha verification is not configured" };
  }

  if (!token || token.length < 10 || token.length > 2048) {
    return { ok: false, error: "Captcha token missing or invalid" };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const form = new URLSearchParams();
    form.set("secret", secret);
    form.set("response", token);
    if (remoteIp && remoteIp !== "unknown") {
      form.set("remoteip", remoteIp);
    }

    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      signal: controller.signal,
    });

    if (!res.ok) {
      return { ok: false, error: "Captcha provider unavailable" };
    }

    const result = (await res.json()) as { success?: boolean };
    if (!result.success) {
      return { ok: false, error: "Captcha verification failed" };
    }

    return { ok: true };
  } catch {
    return { ok: false, error: "Captcha verification timeout" };
  } finally {
    clearTimeout(timeoutId);
  }
}
