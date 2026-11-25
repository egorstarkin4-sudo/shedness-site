import type { SupabaseClient } from "npm:@supabase/supabase-js@2.49.4";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error("Invalid hex encoding");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return toHex(new Uint8Array(digest));
}

export async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return toHex(new Uint8Array(sig));
}

export function generateRandomBase32(byteLength = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);

  let bits = 0;
  let value = 0;
  let output = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32(base32: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = base32.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error("Invalid Base32 character");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function computeTotpCode(secretBase32: string, counter: number): Promise<string> {
  const keyBytes = decodeBase32(secretBase32);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );

  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBuf));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return (binary % 1_000_000).toString().padStart(6, "0");
}

export async function verifyTotpCode(secretBase32: string, code: string): Promise<boolean> {
  const clean = code.trim();
  if (!/^\d{6}$/.test(clean)) return false;

  const step = Math.floor(Date.now() / 1000 / 30);
  for (let delta = -1; delta <= 1; delta++) {
    const expected = await computeTotpCode(secretBase32, step + delta);
    if (constantTimeEqual(expected, clean)) {
      return true;
    }
  }
  return false;
}

async function getAesKey(): Promise<CryptoKey> {
  const hexKey = Deno.env.get("TOTP_ENCRYPTION_KEY");
  if (!hexKey || hexKey.length !== 64) {
    throw new Error("TOTP_ENCRYPTION_KEY must be a 64-char hex string");
  }
  return crypto.subtle.importKey("raw", fromHex(hexKey), { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptSecret(plaintext: string): Promise<{ ciphertext: string; iv: string }> {
  const key = await getAesKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plaintext),
  );
  return {
    ciphertext: toHex(new Uint8Array(encrypted)),
    iv: toHex(iv),
  };
}

export async function decryptSecret(ciphertextHex: string, ivHex: string): Promise<string> {
  const key = await getAesKey();
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromHex(ivHex) },
    key,
    fromHex(ciphertextHex),
  );
  return decoder.decode(decrypted);
}

export function generateLicenseKeyString(durationDays: number): {
  rawKey: string;
  prefix: string;
} {
  const planTag =
    durationDays === 0 ? "RESET" : durationDays < 0 || durationDays >= 9000 ? "LIFE" : `${durationDays}D`;

  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  const chunks: string[] = [];
  for (let c = 0; c < 4; c++) {
    let part = "";
    for (let i = 0; i < 4; i++) {
      part += alphabet[bytes[c * 4 + i] % alphabet.length];
    }
    chunks.push(part);
  }

  const rawKey = `SHEDNESS-${planTag}-${chunks.join("-")}`;
  const prefix = `SHEDNESS-${planTag}-${chunks[0]}-****`;
  return { rawKey, prefix };
}

export async function hashLicenseKey(rawKey: string): Promise<string> {
  const pepper = Deno.env.get("LICENSE_KEY_PEPPER");
  if (!pepper || pepper.length < 32) {
    throw new Error("LICENSE_KEY_PEPPER not configured");
  }
  return sha256Hex(`${pepper}:${rawKey.trim().toUpperCase()}`);
}

export async function signLicenseKeyHmac(
  rawKey: string,
  durationDays: number,
  boundUserId: string | null,
): Promise<string> {
  const secret = Deno.env.get("LICENSE_HMAC_SECRET");
  if (!secret || secret.length < 32) {
    throw new Error("LICENSE_HMAC_SECRET not configured");
  }
  const payload = `${rawKey.trim().toUpperCase()}|${durationDays}|${boundUserId ?? "*"}`;
  return hmacSha256Hex(secret, payload);
}

export async function writeAuditLog(
  serviceClient: SupabaseClient,
  entry: {
    actorId: string | null;
    actorEmail?: string | null;
    action: string;
    targetType?: string;
    targetId?: string;
    ipAddress?: string;
    userAgent?: string;
    metadata?: Record<string, unknown>;
  },
): Promise<void> {
  await serviceClient.from("audit_log").insert({
    actor_id: entry.actorId,
    actor_email: entry.actorEmail ?? null,
    action: entry.action,
    target_type: entry.targetType ?? null,
    target_id: entry.targetId ?? null,
    ip_address: entry.ipAddress ?? null,
    user_agent: entry.userAgent ?? null,
    metadata: entry.metadata ?? {},
  });
}
