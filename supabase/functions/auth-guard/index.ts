import { z } from "npm:zod@3.24.2";
import {
  handleCorsPreflight,
  jsonError,
  jsonResponse,
  validateMutationOrigin,
} from "../_shared/cors.ts";
import { enforceRateLimit, getClientIp, getServiceClient, parseJsonBody } from "../_shared/auth.ts";
import { verifyTurnstile } from "../_shared/turnstile.ts";
import { sha256Hex, writeAuditLog } from "../_shared/crypto.ts";

const GuardSchema = z.object({
  action: z.enum(["login", "register", "reset"]),
  identifier: z.string().trim().min(3).max(120),
  turnstileToken: z.string().min(10).max(2048),
});

Deno.serve(async (req: Request) => {
  const preflight = handleCorsPreflight(req);
  if (preflight) return preflight;
  if (req.method !== "POST") return jsonError(req, "Method not allowed", 405);

  const originCheck = validateMutationOrigin(req);
  if (originCheck) return originCheck;

  const parsed = await parseJsonBody<unknown>(req, 8192);
  if (parsed.error) return jsonError(req, parsed.error, 400);

  const input = GuardSchema.safeParse(parsed.data);
  if (!input.success) return jsonError(req, "Invalid request parameters", 400);

  const ip = getClientIp(req);
  const serviceClient = getServiceClient();

  // IP-level rate limit: max 12 attempts per 5 minutes, block 5 minutes
  const ipRl = await enforceRateLimit(
    serviceClient,
    `auth:${input.data.action}:ip:${ip}`,
    12,
    300,
    300,
  );
  if (!ipRl.allowed) {
    await writeAuditLog(serviceClient, {
      actorId: null,
      action: "security.auth_rate_limited",
      ipAddress: ip,
      metadata: { flow: input.data.action },
    });
    return jsonError(req, "Too many attempts. Please wait a few minutes.", 429);
  }

  // Identifier-level rate limit (hashed so PII is never stored in rate_limits)
  const idHash = await sha256Hex(input.data.identifier.toLowerCase());
  const idRl = await enforceRateLimit(
    serviceClient,
    `auth:${input.data.action}:id:${idHash.slice(0, 24)}`,
    8,
    300,
    300,
  );
  if (!idRl.allowed) {
    return jsonError(req, "Too many attempts for this account. Try again later.", 429);
  }

  const turnstile = await verifyTurnstile(input.data.turnstileToken, ip);
  if (!turnstile.ok) {
    return jsonError(req, turnstile.error ?? "Captcha check failed", 403);
  }

  return jsonResponse(req, { ok: true });
});
