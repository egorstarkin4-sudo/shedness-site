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
import {
  decryptSecret,
  encryptSecret,
  generateRandomBase32,
  sha256Hex,
  toHex,
  verifyTotpCode,
  writeAuditLog,
} from "../_shared/crypto.ts";

const TotpActionSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("status") }),
  z.object({ action: z.literal("setup") }),
  z.object({
    action: z.literal("verify"),
    code: z.string().trim().regex(/^\d{6}$/),
  }),
  z.object({ action: z.literal("logout") }),
]);

const ADMIN_SESSION_TTL_MINUTES = 15;

async function hashAdminSessionToken(rawToken: string): Promise<string> {
  const secret = Deno.env.get("ADMIN_SESSION_SECRET");
  if (!secret || secret.length < 32) {
    throw new Error("ADMIN_SESSION_SECRET not configured");
  }
  return sha256Hex(`${secret}:${rawToken}`);
}

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

  // Allowlist check: hide admin existence with generic 404
  const { data: adminRow } = await serviceClient
    .from("admins")
    .select("user_id")
    .eq("user_id", user.id)
    .maybeSingle();

  if (!adminRow) {
    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "security.non_admin_totp_probe",
      ipAddress: ip,
      userAgent,
    });
    return jsonError(req, "Not found", 404);
  }

  const parsed = await parseJsonBody<unknown>(req, 2048);
  if (parsed.error) return jsonError(req, parsed.error, 400);

  const input = TotpActionSchema.safeParse(parsed.data);
  if (!input.success) return jsonError(req, "Invalid request", 400);

  if (input.data.action === "status") {
    const { data: totp } = await serviceClient
      .from("admin_totp")
      .select("enabled")
      .eq("user_id", user.id)
      .maybeSingle();

    const sessionHeader = req.headers.get("x-admin-session") ?? "";
    let sessionValid = false;
    if (sessionHeader.length >= 32) {
      const tokenHash = await hashAdminSessionToken(sessionHeader);
      const { data: sess } = await serviceClient
        .from("admin_sessions")
        .select("id")
        .eq("user_id", user.id)
        .eq("token_hash", tokenHash)
        .is("revoked_at", null)
        .gt("expires_at", new Date().toISOString())
        .maybeSingle();
      sessionValid = Boolean(sess);
    }

    return jsonResponse(req, {
      ok: true,
      enrolled: Boolean(totp?.enabled),
      session_valid: sessionValid,
    });
  }

  if (input.data.action === "setup") {
    const { data: existing } = await serviceClient
      .from("admin_totp")
      .select("enabled")
      .eq("user_id", user.id)
      .maybeSingle();

    if (existing?.enabled) {
      return jsonError(req, "2FA is already enabled for this administrator", 409);
    }

    const secretBase32 = generateRandomBase32(20);
    const { ciphertext, iv } = await encryptSecret(secretBase32);

    const { error: upsertErr } = await serviceClient.from("admin_totp").upsert({
      user_id: user.id,
      secret_ciphertext: ciphertext,
      secret_iv: iv,
      enabled: false,
      updated_at: new Date().toISOString(),
    });

    if (upsertErr) {
      return jsonError(req, "Unable to initialize 2FA", 500);
    }

    const label = encodeURIComponent(user.email ?? user.id);
    const otpauthUrl = `otpauth://totp/Shedness%20Launcher:${label}?secret=${secretBase32}&issuer=Shedness%20Launcher&algorithm=SHA1&digits=6&period=30`;

    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "admin.totp_setup_initiated",
      ipAddress: ip,
      userAgent,
    });

    return jsonResponse(req, {
      ok: true,
      otpauth_url: otpauthUrl,
      manual_secret: secretBase32,
    });
  }

  if (input.data.action === "verify") {
    const rl = await enforceRateLimit(serviceClient, `totp:verify:${user.id}`, 5, 300, 600);
    if (!rl.allowed) {
      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "security.admin_totp_rate_limited",
        ipAddress: ip,
        userAgent,
      });
      return jsonError(req, "Too many 2FA attempts. Locked temporarily.", 429);
    }

    const { data: totpRow } = await serviceClient
      .from("admin_totp")
      .select("secret_ciphertext, secret_iv, enabled")
      .eq("user_id", user.id)
      .maybeSingle();

    if (!totpRow) {
      return jsonError(req, "2FA is not initialized", 400);
    }

    const secretBase32 = await decryptSecret(totpRow.secret_ciphertext, totpRow.secret_iv);
    const valid = await verifyTotpCode(secretBase32, input.data.code);
    if (!valid) {
      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "security.admin_totp_failed",
        ipAddress: ip,
        userAgent,
      });
      return jsonError(req, "Invalid 2FA code", 401);
    }

    if (!totpRow.enabled) {
      await serviceClient
        .from("admin_totp")
        .update({
          enabled: true,
          verified_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        })
        .eq("user_id", user.id);
    }

    // Revoke older sessions for clean single-session hygiene
    await serviceClient
      .from("admin_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .is("revoked_at", null);

    const rawBytes = crypto.getRandomValues(new Uint8Array(32));
    const sessionToken = toHex(rawBytes);
    const tokenHash = await hashAdminSessionToken(sessionToken);
    const expiresAt = new Date(Date.now() + ADMIN_SESSION_TTL_MINUTES * 60_000).toISOString();

    const { error: sessErr } = await serviceClient.from("admin_sessions").insert({
      user_id: user.id,
      token_hash: tokenHash,
      ip_address: ip,
      user_agent: userAgent,
      expires_at: expiresAt,
    });

    if (sessErr) {
      return jsonError(req, "Unable to create admin session", 500);
    }

    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "admin.totp_verified",
      ipAddress: ip,
      userAgent,
      metadata: { expires_at: expiresAt },
    });

    return jsonResponse(req, {
      ok: true,
      session_token: sessionToken,
      expires_at: expiresAt,
    });
  }

  // logout
  const sessionHeader = req.headers.get("x-admin-session") ?? "";
  if (sessionHeader.length >= 32) {
    const tokenHash = await hashAdminSessionToken(sessionHeader);
    await serviceClient
      .from("admin_sessions")
      .update({ revoked_at: new Date().toISOString() })
      .eq("user_id", user.id)
      .eq("token_hash", tokenHash);
  }

  await writeAuditLog(serviceClient, {
    actorId: user.id,
    actorEmail: user.email,
    action: "admin.session_logged_out",
    ipAddress: ip,
    userAgent,
  });

  return jsonResponse(req, { ok: true });
});
