import { z } from "npm:zod@3.24.2";
import {
  handleCorsPreflight,
  jsonError,
  jsonResponse,
  validateMutationOrigin,
} from "../_shared/cors.ts";
import {
  authenticateRequest,
  enforceRateLimit,
  getServiceClient,
  parseJsonBody,
} from "../_shared/auth.ts";
import { verifyTurnstile } from "../_shared/turnstile.ts";
import {
  constantTimeEqual,
  hashLicenseKey,
  signLicenseKeyHmac,
  writeAuditLog,
} from "../_shared/crypto.ts";

const RedeemSchema = z.object({
  key: z
    .string()
    .trim()
    .min(8)
    .max(64)
    .regex(/^[A-Za-z0-9-]+$/, "Invalid key format"),
  turnstileToken: z.string().min(10).max(2048).optional(),
});

Deno.serve(async (req: Request) => {
  const preflight = handleCorsPreflight(req);
  if (preflight) return preflight;
  if (req.method !== "POST") return jsonError(req, "Method not allowed", 405);

  const originCheck = validateMutationOrigin(req);
  if (originCheck) return originCheck;

  const serviceClient = getServiceClient();
  const auth = await authenticateRequest(req, serviceClient);
  if (!auth.ctx) {
    return jsonError(req, auth.error ?? "Unauthorized", auth.status ?? 401);
  }

  const { user, ip, userAgent } = auth.ctx;

  const parsed = await parseJsonBody<unknown>(req, 4096);
  if (parsed.error) return jsonError(req, parsed.error, 400);

  const input = RedeemSchema.safeParse(parsed.data);
  if (!input.success) return jsonError(req, "Invalid license key format", 400);

  // Strict rate limit against key brute-forcing
  const userRl = await enforceRateLimit(serviceClient, `redeem:user:${user.id}`, 6, 300, 600);
  const ipRl = await enforceRateLimit(serviceClient, `redeem:ip:${ip}`, 10, 300, 600);
  if (!userRl.allowed || !ipRl.allowed) {
    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "security.redeem_rate_limited",
      ipAddress: ip,
      userAgent,
    });
    return jsonError(req, "Too many key redemption attempts. Please wait.", 429);
  }

  if (Deno.env.get("TURNSTILE_SECRET_KEY")) {
    const captcha = await verifyTurnstile(input.data.turnstileToken, ip);
    if (!captcha.ok) {
      return jsonError(req, captcha.error ?? "Captcha verification required", 403);
    }
  }

  const normalizedKey = input.data.key.toUpperCase();
  const keyHash = await hashLicenseKey(normalizedKey);

  // Lookup by salted hash first; fallback only for unhashed legacy /ne keys
  let { data: keyRow } = await serviceClient
    .from("license_keys")
    .select("id, duration_days, bound_user_id, key_hmac, is_used, revoked_at, expires_at, key_prefix")
    .eq("key_hash", keyHash)
    .maybeSingle();

  if (!keyRow) {
    const legacy = await serviceClient
      .from("license_keys")
      .select("id, duration_days, bound_user_id, key_hmac, is_used, revoked_at, expires_at, key_prefix")
      .is("key_hash", null)
      .ilike("code", normalizedKey)
      .maybeSingle();
    keyRow = legacy.data;
  }

  if (!keyRow) {
    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "license.redeem_invalid",
      ipAddress: ip,
      userAgent,
    });
    return jsonError(req, "License key not found or invalid", 400);
  }

  // Verify HMAC signature if key has server HMAC attached
  if (keyRow.key_hmac) {
    const expectedHmac = await signLicenseKeyHmac(
      normalizedKey,
      keyRow.duration_days,
      keyRow.bound_user_id,
    );
    if (!constantTimeEqual(expectedHmac, keyRow.key_hmac)) {
      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "security.license_hmac_mismatch",
        targetType: "license_key",
        targetId: String(keyRow.id),
        ipAddress: ip,
        userAgent,
      });
      return jsonError(req, "License key signature invalid", 403);
    }
  }

  const { data: redeemResult, error: redeemErr } = await serviceClient.rpc(
    "srv_redeem_license_key",
    {
      p_user_id: user.id,
      p_key_id: keyRow.id,
    },
  );

  if (redeemErr || !redeemResult?.ok) {
    const code = redeemResult?.error ?? "redeem_failed";
    const statusMap: Record<string, [string, number]> = {
      key_not_found: ["License key not found", 400],
      key_revoked: ["License key has been revoked", 400],
      key_already_used: ["License key has already been used", 400],
      key_expired: ["License key has expired", 400],
      key_bound_to_another_user: ["This key is bound to a different account", 403],
      account_banned: ["Account is suspended", 403],
    };
    const [msg, status] = statusMap[code] ?? ["Unable to redeem license key", 400];
    return jsonError(req, msg, status);
  }

  await writeAuditLog(serviceClient, {
    actorId: user.id,
    actorEmail: user.email,
    action: "license.redeem_success",
    targetType: "license_key",
    targetId: String(keyRow.id),
    ipAddress: ip,
    userAgent,
    metadata: {
      prefix: keyRow.key_prefix ?? "legacy",
      type: redeemResult.type,
      until: redeemResult.until,
    },
  });

  return jsonResponse(req, {
    ok: true,
    type: redeemResult.type,
    until: redeemResult.until,
  });
});
