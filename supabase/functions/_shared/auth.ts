import { createClient, type SupabaseClient, type User } from "npm:@supabase/supabase-js@2.49.4";

export function getServiceClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) {
    throw new Error("Missing Supabase service configuration");
  }
  return createClient(url, serviceKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

export function getClientIp(req: Request): string {
  const cfIp = req.headers.get("cf-connecting-ip");
  if (cfIp) return cfIp.trim().slice(0, 64);
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim().slice(0, 64);
  return "unknown";
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
    const json = atob(padded);
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export interface AuthContext {
  user: User;
  token: string;
  ip: string;
  userAgent: string;
}

export async function authenticateRequest(
  req: Request,
  serviceClient: SupabaseClient,
): Promise<{ ctx?: AuthContext; error?: string; status?: number }> {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return { error: "Unauthorized", status: 401 };
  }

  const token = authHeader.slice(7).trim();
  if (!token || token.length > 4096) {
    return { error: "Unauthorized", status: 401 };
  }

  // Validate JWT claims locally before network roundtrip
  const payload = decodeJwtPayload(token);
  const nowSec = Math.floor(Date.now() / 1000);
  if (
    !payload ||
    typeof payload.exp !== "number" ||
    payload.exp <= nowSec ||
    payload.aud !== "authenticated" ||
    payload.role !== "authenticated"
  ) {
    return { error: "Session expired or invalid", status: 401 };
  }

  // Cryptographic signature & session check via Supabase Auth
  const { data, error } = await serviceClient.auth.getUser(token);
  if (error || !data?.user) {
    return { error: "Unauthorized", status: 401 };
  }

  return {
    ctx: {
      user: data.user,
      token,
      ip: getClientIp(req),
      userAgent: (req.headers.get("user-agent") ?? "").slice(0, 256),
    },
  };
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retry_after: number;
}

export async function enforceRateLimit(
  serviceClient: SupabaseClient,
  bucketKey: string,
  maxHits: number,
  windowSeconds: number,
  blockSeconds = 60,
): Promise<RateLimitResult> {
  const upstashUrl = Deno.env.get("UPSTASH_REDIS_REST_URL");
  const upstashToken = Deno.env.get("UPSTASH_REDIS_REST_TOKEN");

  // Use Upstash Redis if configured, with strict 3s timeout; fall back to Postgres RPC
  if (upstashUrl && upstashToken) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      const redisKey = `rl:${bucketKey}`;
      const res = await fetch(`${upstashUrl.replace(/\/$/, "")}/pipeline`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${upstashToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify([
          ["INCR", redisKey],
          ["EXPIRE", redisKey, windowSeconds, "NX"],
        ]),
        signal: controller.signal,
      });
      if (res.ok) {
        const body = (await res.json()) as Array<{ result: number }>;
        const hits = Number(body?.[0]?.result ?? 1);
        if (hits > maxHits) {
          return { allowed: false, remaining: 0, retry_after: blockSeconds };
        }
        return { allowed: true, remaining: Math.max(0, maxHits - hits), retry_after: 0 };
      }
    } catch {
      // Fallback to Postgres rate limiter on Upstash network timeout
    } finally {
      clearTimeout(timer);
    }
  }

  const { data, error } = await serviceClient.rpc("consume_rate_limit", {
    p_key: bucketKey,
    p_max: maxHits,
    p_window_seconds: windowSeconds,
    p_block_seconds: blockSeconds,
  });

  if (error || !data) {
    // Fail closed on rate-limit infrastructure error for security-critical routes
    return { allowed: false, remaining: 0, retry_after: 30 };
  }

  return {
    allowed: Boolean(data.allowed),
    remaining: Number(data.remaining ?? 0),
    retry_after: Number(data.retry_after ?? 0),
  };
}

export async function parseJsonBody<T>(
  req: Request,
  maxBytes = 16_384,
): Promise<{ data?: T; error?: string }> {
  const lenHeader = req.headers.get("content-length");
  if (lenHeader && Number(lenHeader) > maxBytes) {
    return { error: "Payload too large" };
  }

  try {
    const raw = await req.text();
    if (raw.length > maxBytes) {
      return { error: "Payload too large" };
    }
    const parsed = raw.trim() ? (JSON.parse(raw) as T) : ({} as T);
    return { data: parsed };
  } catch {
    return { error: "Invalid JSON payload" };
  }
}
