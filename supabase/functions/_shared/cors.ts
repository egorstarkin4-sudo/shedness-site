// Strict CORS allowlist and safe JSON response helpers for Edge Functions

const DEFAULT_ORIGINS = ["http://localhost:3000"];

export function getAllowedOrigins(): string[] {
  const raw = Deno.env.get("ALLOWED_ORIGINS") ?? "";
  const parsed = raw
    .split(",")
    .map((o) => o.trim().replace(/\/$/, ""))
    .filter(Boolean);
  return parsed.length > 0 ? parsed : DEFAULT_ORIGINS;
}

export function isOriginAllowed(origin: string | null): boolean {
  if (!origin) return false;
  const clean = origin.trim().replace(/\/$/, "");
  return getAllowedOrigins().includes(clean);
}

export function buildCorsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  const allowed = origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];

  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "authorization, x-client-info, apikey, content-type, x-admin-session, x-requested-with",
    "Access-Control-Max-Age": "600",
    Vary: "Origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
  };
}

export function handleCorsPreflight(req: Request): Response | null {
  if (req.method === "OPTIONS") {
    const origin = req.headers.get("Origin");
    if (!isOriginAllowed(origin)) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, { status: 204, headers: buildCorsHeaders(req) });
  }
  return null;
}

export function validateMutationOrigin(req: Request): Response | null {
  const origin = req.headers.get("Origin");
  if (!origin || !isOriginAllowed(origin)) {
    return jsonError(req, "Origin not allowed", 403);
  }
  // Require custom header to block simple cross-site form/fetch CSRF requests
  const xrw = req.headers.get("x-requested-with");
  if (xrw !== "ShednessWebClient") {
    return jsonError(req, "Invalid request context", 403);
  }
  return null;
}

export function jsonResponse(req: Request, data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...buildCorsHeaders(req),
      "Content-Type": "application/json; charset=utf-8",
    },
  });
}

export function jsonError(req: Request, message: string, status = 400): Response {
  return jsonResponse(req, { ok: false, error: message }, status);
}
