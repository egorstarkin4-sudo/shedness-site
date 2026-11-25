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
  generateLicenseKeyString,
  hashLicenseKey,
  sha256Hex,
  signLicenseKeyHmac,
  verifyTotpCode,
  writeAuditLog,
} from "../_shared/crypto.ts";

const AdminActionSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("list_users"),
    search: z.string().max(80).optional(),
  }),
  z.object({
    action: z.literal("grant_subscription"),
    targetUserId: z.string().uuid(),
    days: z.number().int().min(1).max(99999),
  }),
  z.object({
    action: z.literal("revoke_subscription"),
    targetUserId: z.string().uuid(),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
  z.object({
    action: z.literal("ban_user"),
    targetUserId: z.string().uuid(),
    banned: z.boolean(),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
  z.object({
    action: z.literal("reset_hwid"),
    targetUserId: z.string().uuid(),
  }),
  z.object({
    action: z.literal("generate_key"),
    durationDays: z.number().int().min(0).max(99999),
    boundUserId: z.string().uuid().nullable().optional(),
    expiresInDays: z.number().int().min(1).max(3650).nullable().optional(),
    permissions: z.array(z.string().min(2).max(40)).max(5).optional(),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
  z.object({
    action: z.literal("revoke_key"),
    keyId: z.number().int().positive(),
    reason: z.string().trim().min(2).max(200),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
  z.object({ action: z.literal("list_keys") }),
  z.object({ action: z.literal("list_releases") }),
  z.object({
    action: z.literal("prepare_release_upload"),
    version: z.string().trim().regex(/^[0-9A-Za-z._-]{1,32}$/),
    platform: z.enum(["windows", "macos", "linux"]),
    fileName: z.string().trim().regex(/^[A-Za-z0-9._-]{3,80}$/),
  }),
  z.object({
    action: z.literal("create_release"),
    version: z.string().trim().regex(/^[0-9A-Za-z._-]{1,32}$/),
    platform: z.enum(["windows", "macos", "linux"]),
    channel: z.enum(["stable", "beta", "alpha"]),
    storagePath: z.string().trim().regex(/^[A-Za-z0-9/_.-]{5,240}$/),
    fileName: z.string().trim().regex(/^[A-Za-z0-9._-]{3,80}$/),
    fileSize: z.number().int().positive().max(524_288_000),
    sha256: z.string().trim().toLowerCase().regex(/^[a-f0-9]{64}$/),
    changelog: z.string().max(2000).default(""),
    minOs: z.string().max(80).default("Windows 10/11 x64"),
    isLatest: z.boolean().default(true),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
  z.object({ action: z.literal("list_audit_logs") }),
  z.object({
    action: z.literal("update_site_config"),
    maintenance: z.boolean(),
    brandName: z.string().trim().min(2).max(60),
    supportEmail: z.string().email().max(120),
    totpCode: z.string().regex(/^\d{6}$/),
  }),
]);

async function verifyAdminSession(
  serviceClient: ReturnType<typeof getServiceClient>,
  userId: string,
  rawSessionToken: string | null,
): Promise<boolean> {
  if (!rawSessionToken || rawSessionToken.length < 32) return false;
  const secret = Deno.env.get("ADMIN_SESSION_SECRET");
  if (!secret || secret.length < 32) return false;

  const tokenHash = await sha256Hex(`${secret}:${rawSessionToken}`);
  const { data: sess } = await serviceClient
    .from("admin_sessions")
    .select("id")
    .eq("user_id", userId)
    .eq("token_hash", tokenHash)
    .is("revoked_at", null)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();

  if (!sess) return false;

  await serviceClient
    .from("admin_sessions")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", sess.id);

  return true;
}

async function verifyCriticalTotp(
  serviceClient: ReturnType<typeof getServiceClient>,
  userId: string,
  code: string,
): Promise<boolean> {
  const { data: totpRow } = await serviceClient
    .from("admin_totp")
    .select("secret_ciphertext, secret_iv, enabled")
    .eq("user_id", userId)
    .maybeSingle();

  if (!totpRow?.enabled) return false;
  const secretBase32 = await decryptSecret(totpRow.secret_ciphertext, totpRow.secret_iv);
  return verifyTotpCode(secretBase32, code);
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

  // 1. Strict allowlist verification in public.admins
  const { data: adminRow } = await serviceClient
    .from("admins")
    .select("user_id")
    .eq("user_id", user.id)
    .maybeSingle();

  if (!adminRow) {
    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "security.unauthorized_admin_attempt",
      ipAddress: ip,
      userAgent,
    });
    return jsonError(req, "Not found", 404);
  }

  // 2. Verify short-lived TOTP-backed admin session
  const sessionOk = await verifyAdminSession(
    serviceClient,
    user.id,
    req.headers.get("x-admin-session"),
  );
  if (!sessionOk) {
    return jsonError(req, "2FA session required or expired", 401);
  }

  const rl = await enforceRateLimit(serviceClient, `admin:${user.id}`, 60, 60, 60);
  if (!rl.allowed) {
    return jsonError(req, "Admin rate limit exceeded", 429);
  }

  const parsed = await parseJsonBody<unknown>(req, 16_384);
  if (parsed.error) return jsonError(req, parsed.error, 400);

  const input = AdminActionSchema.safeParse(parsed.data);
  if (!input.success) return jsonError(req, "Invalid admin request payload", 400);

  const payload = input.data;

  // Re-verify TOTP on critical actions
  if ("totpCode" in payload) {
    const reAuthOk = await verifyCriticalTotp(serviceClient, user.id, payload.totpCode);
    if (!reAuthOk) {
      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "security.admin_reauth_failed",
        ipAddress: ip,
        userAgent,
        metadata: { attempted_action: payload.action },
      });
      return jsonError(req, "Invalid 2FA re-authentication code", 403);
    }
  }

  switch (payload.action) {
    case "list_users": {
      const { data: users, error } = await serviceClient
        .from("profiles")
        .select(
          "id, email, mc_nickname, hwid, subscription_active, subscription_until, subscription_expires_at, is_banned, uid, created_at",
        )
        .order("created_at", { ascending: false })
        .limit(200);

      if (error) return jsonError(req, "Failed to load users", 500);

      const { data: adminsList } = await serviceClient.from("admins").select("user_id");
      const adminSet = new Set((adminsList ?? []).map((a) => a.user_id));

      const search = (payload.search ?? "").trim().toLowerCase();
      const filtered = (users ?? [])
        .map((u) => ({ ...u, is_admin: adminSet.has(u.id) }))
        .filter((u) => {
          if (!search) return true;
          return (
            (u.email ?? "").toLowerCase().includes(search) ||
            (u.mc_nickname ?? "").toLowerCase().includes(search) ||
            String(u.uid ?? "").includes(search)
          );
        });

      return jsonResponse(req, { ok: true, users: filtered });
    }

    case "grant_subscription": {
      const isLifetime = payload.days >= 9000;
      const expTs = isLifetime
        ? null
        : new Date(Date.now() + payload.days * 86_400_000).toISOString();
      const untilText = isLifetime
        ? "Навсегда (Lifetime)"
        : `до ${new Date(expTs!).toLocaleDateString("ru-RU")}`;

      const { error } = await serviceClient
        .from("profiles")
        .update({
          subscription_active: true,
          subscription_until: untilText,
          subscription_expires_at: expTs,
        })
        .eq("id", payload.targetUserId);

      if (error) return jsonError(req, "Failed to grant subscription", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.grant_subscription",
        targetType: "user",
        targetId: payload.targetUserId,
        ipAddress: ip,
        userAgent,
        metadata: { days: payload.days, until: untilText },
      });

      return jsonResponse(req, { ok: true, until: untilText });
    }

    case "revoke_subscription": {
      const { error } = await serviceClient
        .from("profiles")
        .update({
          subscription_active: false,
          subscription_until: "Не активна",
          subscription_expires_at: null,
        })
        .eq("id", payload.targetUserId);

      if (error) return jsonError(req, "Failed to revoke subscription", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.revoke_subscription",
        targetType: "user",
        targetId: payload.targetUserId,
        ipAddress: ip,
        userAgent,
      });

      return jsonResponse(req, { ok: true });
    }

    case "ban_user": {
      if (payload.targetUserId === user.id) {
        return jsonError(req, "Cannot ban your own admin account", 400);
      }
      const { data: targetAdmin } = await serviceClient
        .from("admins")
        .select("user_id")
        .eq("user_id", payload.targetUserId)
        .maybeSingle();
      if (targetAdmin) {
        return jsonError(req, "Cannot ban an administrator account", 403);
      }

      const { error } = await serviceClient
        .from("profiles")
        .update(
          payload.banned
            ? {
                is_banned: true,
                subscription_active: false,
                subscription_until: "BANNED",
                subscription_expires_at: null,
                hwid: "BANNED",
              }
            : {
                is_banned: false,
                subscription_active: false,
                subscription_until: "Не активна",
                subscription_expires_at: null,
                hwid: null,
              },
        )
        .eq("id", payload.targetUserId);

      if (error) return jsonError(req, "Failed to update ban state", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: payload.banned ? "admin.ban_user" : "admin.unban_user",
        targetType: "user",
        targetId: payload.targetUserId,
        ipAddress: ip,
        userAgent,
      });

      return jsonResponse(req, { ok: true });
    }

    case "reset_hwid": {
      const { error } = await serviceClient
        .from("profiles")
        .update({ hwid: null })
        .eq("id", payload.targetUserId);

      if (error) return jsonError(req, "Failed to reset HWID", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.reset_hwid",
        targetType: "user",
        targetId: payload.targetUserId,
        ipAddress: ip,
        userAgent,
      });

      return jsonResponse(req, { ok: true });
    }

    case "generate_key": {
      const { rawKey, prefix } = generateLicenseKeyString(payload.durationDays);
      const keyHash = await hashLicenseKey(rawKey);
      const boundUserId = payload.boundUserId ?? null;
      const keyHmac = await signLicenseKeyHmac(rawKey, payload.durationDays, boundUserId);
      const expiresAt = payload.expiresInDays
        ? new Date(Date.now() + payload.expiresInDays * 86_400_000).toISOString()
        : null;

      // Store ONLY hash, HMAC, and masked prefix — never plaintext key!
      const { data: inserted, error } = await serviceClient
        .from("license_keys")
        .insert({
          code: null,
          key_hash: keyHash,
          key_hmac: keyHmac,
          key_prefix: prefix,
          duration_days: payload.durationDays,
          bound_user_id: boundUserId,
          permissions: payload.permissions ?? ["launcher:download"],
          expires_at: expiresAt,
          created_by: user.id,
          is_used: false,
        })
        .select("id, key_prefix, duration_days, expires_at, created_at")
        .single();

      if (error || !inserted) return jsonError(req, "Failed to generate license key", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.generate_key",
        targetType: "license_key",
        targetId: String(inserted.id),
        ipAddress: ip,
        userAgent,
        metadata: {
          prefix,
          duration_days: payload.durationDays,
          bound_user_id: boundUserId,
          expires_at: expiresAt,
        },
      });

      // Return rawKey once at creation time so admin can copy/deliver it
      return jsonResponse(req, {
        ok: true,
        key: rawKey,
        record: inserted,
      });
    }

    case "revoke_key": {
      const { error } = await serviceClient
        .from("license_keys")
        .update({
          revoked_at: new Date().toISOString(),
          revoked_reason: payload.reason,
        })
        .eq("id", payload.keyId)
        .is("revoked_at", null);

      if (error) return jsonError(req, "Failed to revoke key", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.revoke_key",
        targetType: "license_key",
        targetId: String(payload.keyId),
        ipAddress: ip,
        userAgent,
        metadata: { reason: payload.reason },
      });

      return jsonResponse(req, { ok: true });
    }

    case "list_keys": {
      const { data: keys, error } = await serviceClient
        .from("license_keys")
        .select(
          "id, key_prefix, duration_days, is_used, used_by, bound_user_id, permissions, expires_at, revoked_at, revoked_reason, created_at, used_at",
        )
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) return jsonError(req, "Failed to load keys", 500);
      return jsonResponse(req, { ok: true, keys: keys ?? [] });
    }

    case "list_releases": {
      const { data: releases, error } = await serviceClient
        .from("releases")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(50);

      if (error) return jsonError(req, "Failed to load releases", 500);
      return jsonResponse(req, { ok: true, releases: releases ?? [] });
    }

    case "prepare_release_upload": {
      const storagePath = `${payload.platform}/${payload.version}/${payload.fileName}`;
      if (storagePath.includes("..")) {
        return jsonError(req, "Invalid storage path", 400);
      }

      const { data: uploadData, error } = await serviceClient.storage
        .from("launcher-releases")
        .createSignedUploadUrl(storagePath, { upsert: true });

      if (error || !uploadData) {
        return jsonError(req, "Failed to prepare upload URL", 500);
      }

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.prepare_release_upload",
        targetType: "release",
        targetId: storagePath,
        ipAddress: ip,
        userAgent,
      });

      return jsonResponse(req, {
        ok: true,
        storage_path: storagePath,
        signed_url: uploadData.signedUrl,
        token: uploadData.token,
      });
    }

    case "create_release": {
      if (payload.storagePath.includes("..") || payload.storagePath.startsWith("/")) {
        return jsonError(req, "Invalid storage path", 400);
      }

      if (payload.isLatest) {
        await serviceClient
          .from("releases")
          .update({ is_latest: false })
          .eq("platform", payload.platform)
          .eq("is_latest", true);
      }

      const { data: release, error } = await serviceClient
        .from("releases")
        .upsert(
          {
            version: payload.version,
            platform: payload.platform,
            channel: payload.channel,
            storage_path: payload.storagePath,
            file_name: payload.fileName,
            file_size: payload.fileSize,
            sha256: payload.sha256,
            changelog: payload.changelog,
            min_os: payload.minOs,
            is_latest: payload.isLatest,
            is_active: true,
            created_by: user.id,
          },
          { onConflict: "version,platform" },
        )
        .select("*")
        .single();

      if (error || !release) {
        return jsonError(req, "Failed to register release", 500);
      }

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.create_release",
        targetType: "release",
        targetId: release.id,
        ipAddress: ip,
        userAgent,
        metadata: {
          version: payload.version,
          platform: payload.platform,
          sha256: payload.sha256,
        },
      });

      return jsonResponse(req, { ok: true, release });
    }

    case "list_audit_logs": {
      const { data: logs, error } = await serviceClient
        .from("audit_log")
        .select("id, actor_email, action, target_type, target_id, ip_address, metadata, created_at")
        .order("created_at", { ascending: false })
        .limit(100);

      if (error) return jsonError(req, "Failed to load audit log", 500);
      return jsonResponse(req, { ok: true, logs: logs ?? [] });
    }

    case "update_site_config": {
      const { error } = await serviceClient.from("site_config").upsert({
        key: "main",
        value: {
          brand_name: payload.brandName,
          maintenance: payload.maintenance,
          support_email: payload.supportEmail,
        },
        updated_at: new Date().toISOString(),
      });

      if (error) return jsonError(req, "Failed to update site config", 500);

      await writeAuditLog(serviceClient, {
        actorId: user.id,
        actorEmail: user.email,
        action: "admin.update_site_config",
        targetType: "site_config",
        targetId: "main",
        ipAddress: ip,
        userAgent,
        metadata: { maintenance: payload.maintenance, brandName: payload.brandName },
      });

      return jsonResponse(req, { ok: true });
    }
  }
});
