import { getSupabaseClient, hideBanner, invokeEdge, showBanner } from "./api";

interface AdminUserRow {
  id: string;
  email: string;
  mc_nickname: string;
  hwid: string | null;
  subscription_active: boolean;
  subscription_until: string;
  is_banned: boolean;
  uid: number;
}

interface AdminKeyRow {
  id: number;
  key_prefix: string;
  duration_days: number;
  is_used: boolean;
  used_by: string | null;
  revoked_at: string | null;
}

interface AuditLogRow {
  id: number;
  actor_email: string | null;
  action: string;
  ip_address: string | null;
  created_at: string;
}

let sessionToken = "";

function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

async function sha256File(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function getJwt(): Promise<string | null> {
  const supabase = getSupabaseClient();
  if (!supabase) return null;
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}

async function adminAction<T>(payload: Record<string, unknown>): Promise<T | null> {
  const jwt = await getJwt();
  const alertEl = $("admin-alert");
  if (!jwt || !sessionToken) {
    showBanner(alertEl, "Требуется активная 2FA-сессия", "error");
    return null;
  }

  const res = await invokeEdge<T>("admin-actions", payload, {
    accessToken: jwt,
    adminSessionToken: sessionToken,
  });

  if (!res.ok) {
    if (res.status === 401) {
      sessionToken = "";
      $("admin-console")?.classList.add("hidden");
      $("admin-totp-gate")?.classList.remove("hidden");
    }
    showBanner(alertEl, res.error ?? "Ошибка действия", "error");
    return null;
  }
  return res.data ?? null;
}

async function refreshUsers(): Promise<void> {
  const search = (($("admin-user-search") as HTMLInputElement | null)?.value ?? "").trim();
  const data = await adminAction<{ users: AdminUserRow[] }>({ action: "list_users", search });
  const tbody = $("admin-users-tbody");
  if (!data || !tbody) return;

  tbody.replaceChildren();
  data.users.forEach((u) => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid rgba(255,255,255,0.08)";

    const tdUid = document.createElement("td");
    tdUid.style.padding = "10px 6px";
    tdUid.textContent = `#${u.uid}`;

    const tdUser = document.createElement("td");
    tdUser.style.padding = "10px 6px";
    const strong = document.createElement("strong");
    strong.textContent = u.mc_nickname || "—";
    const sub = document.createElement("div");
    sub.style.fontSize = "11.5px";
    sub.style.color = "var(--text-secondary)";
    sub.textContent = u.email;
    tdUser.append(strong, sub);

    const tdSub = document.createElement("td");
    tdSub.style.padding = "10px 6px";
    tdSub.textContent = u.subscription_until;

    const tdAct = document.createElement("td");
    tdAct.style.padding = "10px 6px";
    tdAct.style.display = "flex";
    tdAct.style.gap = "6px";

    const btnGrant = document.createElement("button");
    btnGrant.type = "button";
    btnGrant.className = "btn-glass";
    btnGrant.style.padding = "4px 8px";
    btnGrant.style.fontSize = "11.5px";
    btnGrant.textContent = "+30д";
    btnGrant.onclick = async () => {
      await adminAction({ action: "grant_subscription", targetUserId: u.id, days: 30 });
      await refreshUsers();
    };

    const btnReset = document.createElement("button");
    btnReset.type = "button";
    btnReset.className = "btn-glass";
    btnReset.style.padding = "4px 8px";
    btnReset.style.fontSize = "11.5px";
    btnReset.textContent = "Reset HWID";
    btnReset.onclick = async () => {
      await adminAction({ action: "reset_hwid", targetUserId: u.id });
      await refreshUsers();
    };

    tdAct.append(btnGrant, btnReset);
    tr.append(tdUid, tdUser, tdSub, tdAct);
    tbody.appendChild(tr);
  });
}

async function refreshKeys(): Promise<void> {
  const data = await adminAction<{ keys: AdminKeyRow[] }>({ action: "list_keys" });
  const tbody = $("admin-keys-tbody");
  if (!data || !tbody) return;

  tbody.replaceChildren();
  data.keys.forEach((k) => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid rgba(255,255,255,0.08)";

    const tdPref = document.createElement("td");
    tdPref.style.padding = "8px 6px";
    tdPref.style.fontFamily = "monospace";
    tdPref.textContent = k.key_prefix;

    const tdDur = document.createElement("td");
    tdDur.style.padding = "8px 6px";
    tdDur.textContent = k.duration_days === 0 ? "HWID Reset" : `${k.duration_days}d`;

    const tdStatus = document.createElement("td");
    tdStatus.style.padding = "8px 6px";
    tdStatus.textContent = k.revoked_at
      ? "Отозван"
      : k.is_used
        ? `Использован (${k.used_by ?? ""})`
        : "Активен";

    tr.append(tdPref, tdDur, tdStatus);
    tbody.appendChild(tr);
  });
}

async function refreshAudit(): Promise<void> {
  const data = await adminAction<{ logs: AuditLogRow[] }>({ action: "list_audit_logs" });
  const tbody = $("admin-audit-tbody");
  if (!data || !tbody) return;

  tbody.replaceChildren();
  data.logs.forEach((log) => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid rgba(255,255,255,0.08)";

    const tdTime = document.createElement("td");
    tdTime.style.padding = "8px 6px";
    tdTime.textContent = new Date(log.created_at).toLocaleString("ru-RU");

    const tdActor = document.createElement("td");
    tdActor.style.padding = "8px 6px";
    tdActor.textContent = log.actor_email ?? "system";

    const tdAct = document.createElement("td");
    tdAct.style.padding = "8px 6px";
    tdAct.style.fontFamily = "monospace";
    tdAct.textContent = log.action;

    const tdIp = document.createElement("td");
    tdIp.style.padding = "8px 6px";
    tdIp.textContent = log.ip_address ?? "—";

    tr.append(tdTime, tdActor, tdAct, tdIp);
    tbody.appendChild(tr);
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  const supabase = getSupabaseClient();
  const notFoundEl = $("admin-404");
  const gateEl = $("admin-totp-gate");
  const consoleEl = $("admin-console");
  const alertEl = $("admin-alert");

  if (!supabase) {
    notFoundEl?.classList.remove("hidden");
    return;
  }

  const { data: userRes } = await supabase.auth.getUser();
  if (!userRes.user) {
    notFoundEl?.classList.remove("hidden");
    return;
  }

  // Allowlist check via RLS (admins_select_self)
  const { data: adminRow } = await supabase
    .from("admins")
    .select("user_id")
    .eq("user_id", userRes.user.id)
    .maybeSingle();

  if (!adminRow) {
    notFoundEl?.classList.remove("hidden");
    return;
  }

  const jwt = await getJwt();
  if (!jwt) {
    notFoundEl?.classList.remove("hidden");
    return;
  }

  const statusRes = await invokeEdge<{ enrolled: boolean; session_valid: boolean }>(
    "admin-totp",
    { action: "status" },
    { accessToken: jwt },
  );

  if (!statusRes.ok || !statusRes.data) {
    notFoundEl?.classList.remove("hidden");
    return;
  }

  gateEl?.classList.remove("hidden");
  if (!statusRes.data.enrolled) {
    $("btn-init-totp")?.classList.remove("hidden");
  } else {
    $("totp-verify-form")?.classList.remove("hidden");
  }

  $("btn-init-totp")?.addEventListener("click", async () => {
    hideBanner(alertEl);
    const token = await getJwt();
    if (!token) return;
    const res = await invokeEdge<{ manual_secret: string; otpauth_url: string }>(
      "admin-totp",
      { action: "setup" },
      { accessToken: token },
    );
    if (!res.ok || !res.data) {
      showBanner(alertEl, res.error ?? "Ошибка настройки 2FA", "error");
      return;
    }
    const box = $("totp-secret-box");
    const secretText = $("totp-manual-secret");
    if (secretText) secretText.textContent = res.data.manual_secret;
    box?.classList.remove("hidden");
    $("btn-init-totp")?.classList.add("hidden");
    $("totp-verify-form")?.classList.remove("hidden");
  });

  $("totp-verify-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const token = await getJwt();
    if (!token) return;
    const code = (($("totp-code-input") as HTMLInputElement | null)?.value ?? "").trim();

    const res = await invokeEdge<{ session_token: string; expires_at: string }>(
      "admin-totp",
      { action: "verify", code },
      { accessToken: token },
    );
    if (!res.ok || !res.data?.session_token) {
      showBanner(alertEl, res.error ?? "Неверный код 2FA", "error");
      return;
    }

    sessionToken = res.data.session_token;
    gateEl?.classList.add("hidden");
    consoleEl?.classList.remove("hidden");
    await Promise.all([refreshUsers(), refreshKeys(), refreshAudit()]);
  });

  $("btn-search-users")?.addEventListener("click", () => void refreshUsers());

  $("gen-key-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const days = Number(($("gen-key-days") as HTMLSelectElement | null)?.value ?? 30);
    const totpCode = (($("admin-reauth-totp") as HTMLInputElement | null)?.value ?? "").trim();
    if (!/^\d{6}$/.test(totpCode)) {
      showBanner(alertEl, "Введите 6-значный TOTP код подтверждения", "error");
      return;
    }

    const res = await adminAction<{ key: string }>({
      action: "generate_key",
      durationDays: days,
      totpCode,
    });
    if (res?.key) {
      const out = $("generated-key-out");
      if (out) {
        out.textContent = res.key;
        out.classList.remove("hidden");
      }
      await refreshKeys();
    }
  });

  $("upload-release-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const fileInput = $("rel-file") as HTMLInputElement | null;
    const file = fileInput?.files?.[0];
    if (!file) return;

    const version = (($("rel-version") as HTMLInputElement | null)?.value ?? "").trim();
    const platform = ($("rel-platform") as HTMLSelectElement | null)?.value as
      | "windows"
      | "macos"
      | "linux";
    const channel = ($("rel-channel") as HTMLSelectElement | null)?.value as
      | "stable"
      | "beta"
      | "alpha";
    const totpCode = (($("admin-reauth-totp") as HTMLInputElement | null)?.value ?? "").trim();
    if (!/^\d{6}$/.test(totpCode)) {
      showBanner(alertEl, "Введите 6-значный TOTP код подтверждения", "error");
      return;
    }

    const safeFileName = file.name.replace(/[^A-Za-z0-9._-]/g, "_");
    const prep = await adminAction<{ storage_path: string; signed_url: string }>({
      action: "prepare_release_upload",
      version,
      platform,
      fileName: safeFileName,
    });
    if (!prep) return;

    const putRes = await fetch(prep.signed_url, {
      method: "PUT",
      headers: { "Content-Type": file.type || "application/octet-stream" },
      body: file,
    });
    if (!putRes.ok) {
      showBanner(alertEl, "Ошибка загрузки файла в приватное хранилище", "error");
      return;
    }

    const sha256 = await sha256File(file);
    const created = await adminAction<{ release: { version: string } }>({
      action: "create_release",
      version,
      platform,
      channel,
      storagePath: prep.storage_path,
      fileName: safeFileName,
      fileSize: file.size,
      sha256,
      isLatest: true,
      totpCode,
    });
    if (created) {
      showBanner(alertEl, `Релиз v${created.release.version} опубликован (SHA-256: ${sha256})`, "success");
      await refreshAudit();
    }
  });
});
