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
import { writeAuditLog } from "../_shared/crypto.ts";

const DownloadSchema = z.object({
  releaseId: z.string().uuid().optional(),
  platform: z.enum(["windows", "macos", "linux"]).default("windows"),
  turnstileToken: z.string().min(10).max(2048).optional(),
});

function isSafeStoragePath(path: string): boolean {
  if (!path || path.length > 260) return false;
  if (path.includes("..") || path.startsWith("/") || path.includes("\\")) return false;
  return /^[a-z0-9/_.-]+$/i.test(path);
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

  const parsed = await parseJsonBody<unknown>(req, 4096);
  if (parsed.error) return jsonError(req, parsed.error, 400);

  const input = DownloadSchema.safeParse(parsed.data);
  if (!input.success) return jsonError(req, "Invalid download parameters", 400);

  // Rate limit per user + per IP to prevent scraping/bandwidth abuse
  const userRl = await enforceRateLimit(serviceClient, `dl:user:${user.id}`, 10, 600, 300);
  const ipRl = await enforceRateLimit(serviceClient, `dl:ip:${ip}`, 20, 600, 300);
  if (!userRl.allowed || !ipRl.allowed) {
    await writeAuditLog(serviceClient, {
      actorId: user.id,
      actorEmail: user.email,
      action: "security.download_rate_limited",
      ipAddress: ip,
      userAgent,
    });
    return jsonError(req, "Download rate limit exceeded. Please wait before trying again.", 429);
  }

  // Verify Turnstile if configured in environment
  if (Deno.env.get("TURNSTILE_SECRET_KEY")) {
    const captcha = await verifyTurnstile(input.data.turnstileToken, ip);
    if (!captcha.ok) {
      return jsonError(req, captcha.error ?? "Captcha verification required", 403);
    }
  }

  // Verify license & ban status on server
  const [{ data: profile }, { data: adminRow }] = await Promise.all([
    serviceClient
      .from("profiles")
      .select("subscription_active, subscription_expires_at, is_banned")
      .eq("id", user.id)
      .maybeSingle(),
    serviceClient.from("admins").select("user_id").eq("user_id", user.id).maybeSingle(),
  ]);

  const isAdmin = Boolean(adminRow);
  if (profile?.is_banned) {
    return jsonError(req, "Account access is suspended", 403);
  }

  const notExpired =
    !profile?.subscription_expires_at ||
    new Date(profile.subscription_expires_at).getTime() > Date.now();
  const hasLicense = Boolean(profile?.subscription_active && notExpired);

  if (!hasLicense && !isAdmin) {
    return jsonError(req, "Active license required to download Shedness Launcher", 403);
  }

  // Locate requested or latest active release
  let releaseQuery = serviceClient
    .from("releases")
    .select("id, version, platform, channel, storage_path, file_name, file_size, sha256, min_os")
    .eq("is_active", true);

  if (input.data.releaseId) {
    releaseQuery = releaseQuery.eq("id", input.data.releaseId);
  } else {
    releaseQuery = releaseQuery
      .eq("platform", input.data.platform)
      .order("is_latest", { ascending: false })
      .order("created_at", { ascending: false })
      .limit(1);
  }

  const { data: release, error: relErr } = await releaseQuery.maybeSingle();
  if (relErr || !release) {
    return jsonError(req, "Requested release is unavailable", 404);
  }

  if (!isSafeStoragePath(release.storage_path)) {
    return jsonError(req, "Release configuration invalid", 500);
  }

  // Generate 60-second ephemeral signed URL from private bucket
  const TTL_SECONDS = 60;
  const { data: signed, error: signErr } = await serviceClient.storage
    .from("launcher-releases")
    .createSignedUrl(release.storage_path, TTL_SECONDS, {
      download: release.file_name,
    });

  if (signErr || !signed?.signedUrl) {
    return jsonError(req, "Unable to issue download link", 500);
  }

  await serviceClient.from("download_logs").insert({
    user_id: user.id,
    release_id: release.id,
    ip_address: ip,
    user_agent: userAgent,
  });

  await writeAuditLog(serviceClient, {
    actorId: user.id,
    actorEmail: user.email,
    action: "release.download_signed_url",
    targetType: "release",
    targetId: release.id,
    ipAddress: ip,
    userAgent,
    metadata: { version: release.version, platform: release.platform },
  });

  return jsonResponse(req, {
    ok: true,
    url: signed.signedUrl,
    expires_in: TTL_SECONDS,
    release: {
      id: release.id,
      version: release.version,
      platform: release.platform,
      channel: release.channel,
      file_name: release.file_name,
      file_size: release.file_size,
      sha256: release.sha256,
      min_os: release.min_os,
    },
  });
});
