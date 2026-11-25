import { isSupabaseConfigured } from "./config";
import { getSupabaseClient, hideBanner, invokeEdge, mountTurnstile, showBanner } from "./api";

interface ProfileRow {
  id: string;
  mc_nickname: string | null;
  avatar_url: string | null;
  hwid: string | null;
  subscription_active: boolean;
  subscription_until: string | null;
  subscription_expires_at: string | null;
  is_banned: boolean;
  uid: number | null;
}

interface PublicRelease {
  id: string;
  version: string;
  platform: "windows" | "macos" | "linux";
  channel: string;
  file_name: string;
  file_size: number;
  sha256: string;
  min_os: string;
  is_latest: boolean;
}

interface DownloadResp {
  url: string;
  expires_in: number;
  release: PublicRelease;
}

const SAFE_AVATARS = ["./assets/img/logo.png", "./assets/img/snowflake.png"];
const LAUNCHER_HANDOFF_KEY = "shedness_launcher_handoff";

interface LauncherHandoff {
  port: number;
  state: string;
}

let authMode: "login" | "register" = "login";
let turnstileToken = "";
let selectedPlatform: "windows" | "macos" | "linux" = "windows";
let releasesCache: PublicRelease[] = [];
let activeHandoff: LauncherHandoff | null = null;
let handoffSent = false;

function readLauncherHandoff(): LauncherHandoff | null {
  try {
    const params = new URLSearchParams(window.location.search);
    const rawPort = params.get("launcher_port");
    const rawState = params.get("launcher_state");
    if (rawPort && rawState) {
      const port = Number(rawPort);
      if (
        Number.isInteger(port) &&
        port >= 1024 &&
        port <= 65535 &&
        /^[A-Za-z0-9_-]{16,128}$/.test(rawState)
      ) {
        const val = { port, state: rawState };
        sessionStorage.setItem(LAUNCHER_HANDOFF_KEY, JSON.stringify(val));
        return val;
      }
    }
    const stored = sessionStorage.getItem(LAUNCHER_HANDOFF_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Partial<LauncherHandoff>;
      if (
        typeof parsed.port === "number" &&
        Number.isInteger(parsed.port) &&
        parsed.port >= 1024 &&
        parsed.port <= 65535 &&
        typeof parsed.state === "string" &&
        /^[A-Za-z0-9_-]{16,128}$/.test(parsed.state)
      ) {
        return { port: parsed.port, state: parsed.state };
      }
    }
  } catch {
    // Ignore storage errors
  }
  return null;
}

function clearLauncherHandoff(): void {
  activeHandoff = null;
  try {
    sessionStorage.removeItem(LAUNCHER_HANDOFF_KEY);
  } catch {
    // Ignore storage errors
  }
}

async function sendSessionToLauncher(): Promise<boolean> {
  if (!activeHandoff || handoffSent) return false;
  const supabase = getSupabaseClient();
  if (!supabase) return false;

  const { data: sess } = await supabase.auth.getSession();
  const accessToken = sess.session?.access_token;
  const refreshToken = sess.session?.refresh_token ?? "";
  if (!accessToken) return false;

  const { port, state } = activeHandoff;
  handoffSent = true;
  clearLauncherHandoff();

  const hashParams = new URLSearchParams({
    access_token: accessToken,
    refresh_token: refreshToken,
    state,
  });
  window.location.assign(`http://127.0.0.1:${port}/callback#${hashParams.toString()}`);
  return true;
}

function renderLauncherBanner(
  loggedIn: boolean,
  nick?: string,
  email?: string,
): void {
  const banner = $("launcher-auth-banner");
  const desc = $("launcher-banner-desc");
  const actions = $("launcher-banner-actions");
  const btnContinue = $("btn-launcher-continue");
  if (!banner || !desc || !actions) return;

  if (!activeHandoff) {
    banner.classList.add("hidden");
    return;
  }

  banner.classList.remove("hidden");
  if (!loggedIn) {
    desc.textContent =
      "Войдите в аккаунт или зарегистрируйтесь ниже — данные автоматически передадутся в Shedness Launcher.";
    actions.classList.add("hidden");
  } else {
    const label = nick || email || "Игрок";
    desc.textContent = `Вы авторизованы на сайте как ${label}${email ? ` (${email})` : ""}. Подтвердите вход в лаунчер или смените аккаунт.`;
    if (btnContinue) btnContinue.textContent = `Войти в лаунчер как ${nick || "Игрок"}`;
    actions.classList.remove("hidden");
  }
}

function $(id: string): HTMLElement | null {
  return document.getElementById(id);
}

function hasValidLicense(p: ProfileRow | null): boolean {
  if (!p || p.is_banned || !p.subscription_active) return false;
  if (!p.subscription_expires_at) return true;
  return new Date(p.subscription_expires_at).getTime() > Date.now();
}

function renderReleaseBox(): void {
  const select = $("release-select") as HTMLSelectElement | null;
  const shaBox = $("release-sha-box");
  const shaText = $("release-sha-text");
  const fileMeta = $("release-file-meta");
  const btnDownload = $("btn-download-launcher") as HTMLButtonElement | null;
  if (!select) return;

  const list = releasesCache.filter((r) => r.platform === selectedPlatform);
  select.replaceChildren();

  if (list.length === 0) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = `Релизы для ${selectedPlatform.toUpperCase()} пока не загружены`;
    select.appendChild(opt);
    shaBox?.classList.add("hidden");
    if (btnDownload) btnDownload.disabled = true;
    return;
  }

  list.forEach((rel) => {
    const opt = document.createElement("option");
    opt.value = rel.id;
    opt.textContent = `v${rel.version} (${rel.channel}) — ${(rel.file_size / (1024 * 1024)).toFixed(1)} MB${rel.is_latest ? " [Latest]" : ""}`;
    select.appendChild(opt);
  });

  const updateMeta = () => {
    const active = list.find((r) => r.id === select.value) ?? list[0];
    if (active && shaText && fileMeta && shaBox) {
      fileMeta.textContent = `Файл: ${active.file_name} • ${active.min_os}`;
      shaText.textContent = active.sha256;
      shaBox.classList.remove("hidden");
    }
    if (btnDownload) btnDownload.disabled = !active;
  };

  select.onchange = updateMeta;
  updateMeta();
}

async function loadProfile(): Promise<void> {
  const supabase = getSupabaseClient();
  const alertEl = $("profile-alert");
  const authSection = $("auth-section");
  const dashSection = $("dashboard-section");
  const configNotice = $("config-notice");

  if (!supabase || !isSupabaseConfigured()) {
    configNotice?.classList.remove("hidden");
    authSection?.classList.add("hidden");
    dashSection?.classList.add("hidden");
    return;
  }

  const { data: userRes } = await supabase.auth.getUser();
  const user = userRes.user;
  if (!user) {
    authSection?.classList.remove("hidden");
    dashSection?.classList.add("hidden");
    renderLauncherBanner(false);
    return;
  }

  authSection?.classList.add("hidden");
  dashSection?.classList.remove("hidden");

  let [{ data: prof, error: profErr }, { data: rels }] = await Promise.all([
    supabase
      .from("profiles")
      .select(
        "id, mc_nickname, avatar_url, hwid, subscription_active, subscription_until, subscription_expires_at, is_banned, uid",
      )
      .eq("id", user.id)
      .maybeSingle(),
    supabase.rpc("get_public_releases"),
  ]);

  if (profErr) {
    showBanner(alertEl, `Ошибка загрузки профиля: ${profErr.message}`, "error");
    return;
  }

  if (!prof) {
    const { error: ensureErr } = await supabase.rpc("ensure_my_profile");
    if (ensureErr) {
      showBanner(alertEl, `Ошибка инициализации профиля: ${ensureErr.message}`, "error");
      return;
    }
    const retry = await supabase
      .from("profiles")
      .select(
        "id, mc_nickname, avatar_url, hwid, subscription_active, subscription_until, subscription_expires_at, is_banned, uid",
      )
      .eq("id", user.id)
      .maybeSingle();
    prof = retry.data;
    if (retry.error) {
      showBanner(alertEl, `Ошибка чтения профиля: ${retry.error.message}`, "error");
      return;
    }
  }

  const profile = (prof as ProfileRow | null) ?? null;
  if (Array.isArray(rels)) {
    releasesCache = rels as PublicRelease[];
  }

  const nickEl = $("prof-nick");
  const uidEl = $("prof-uid");
  const emailEl = $("prof-email");
  const avatarImg = $("prof-avatar") as HTMLImageElement | null;
  const editNick = $("edit-nick") as HTMLInputElement | null;
  const subStatus = $("prof-sub-status");
  const subUntil = $("prof-sub-until");
  const hwidVal = $("prof-hwid");
  const dlLocked = $("download-locked");
  const dlControls = $("download-controls");

  if (nickEl) nickEl.textContent = profile?.mc_nickname || "Игрок";
  if (uidEl) uidEl.textContent = `UID #${profile?.uid ?? "—"}`;
  if (emailEl) emailEl.textContent = user.email ?? "";
  if (editNick) editNick.value = profile?.mc_nickname ?? "";

  const safeAvatar =
    profile?.avatar_url && SAFE_AVATARS.includes(profile.avatar_url)
      ? profile.avatar_url
      : SAFE_AVATARS[0];
  if (avatarImg) avatarImg.src = safeAvatar;

  const active = hasValidLicense(profile);
  if (subStatus) {
    subStatus.textContent = profile?.is_banned
      ? "Заблокирован"
      : active
        ? "Активна"
        : "Не активна";
    subStatus.style.color = profile?.is_banned ? "#FCA5A5" : active ? "#4ADE80" : "#F4F4F6";
  }
  if (subUntil) subUntil.textContent = profile?.subscription_until || "Требуется ключ";
  if (hwidVal) hwidVal.textContent = profile?.hwid || "Не привязан";

  if (active) {
    dlLocked?.classList.add("hidden");
    dlControls?.classList.remove("hidden");
    renderReleaseBox();
  } else {
    dlLocked?.classList.remove("hidden");
    dlControls?.classList.add("hidden");
  }

  renderLauncherBanner(true, profile?.mc_nickname || undefined, user.email ?? undefined);
  hideBanner(alertEl);
}

document.addEventListener("DOMContentLoaded", () => {
  activeHandoff = readLauncherHandoff();
  const alertEl = $("profile-alert");

  $("btn-launcher-continue")?.addEventListener("click", () => {
    void sendSessionToLauncher();
  });

  $("btn-launcher-switch")?.addEventListener("click", async () => {
    const supabase = getSupabaseClient();
    if (!supabase) return;
    await supabase.auth.signOut({ scope: "local" });
    await loadProfile();
  });
  const authTurnstile = mountTurnstile($("auth-turnstile"), (t) => {
    turnstileToken = t;
  });
  const redeemTurnstile = mountTurnstile($("redeem-turnstile"), (t) => {
    turnstileToken = t;
  });

  // Auth tabs
  const tabLogin = $("tab-login");
  const tabRegister = $("tab-register");
  const nickWrap = $("reg-nick-wrap");
  const authSubmitBtn = $("btn-auth-submit") as HTMLButtonElement | null;

  tabLogin?.addEventListener("click", () => {
    authMode = "login";
    tabLogin.className = "btn-primary";
    if (tabRegister) tabRegister.className = "btn-glass";
    nickWrap?.classList.add("hidden");
    if (authSubmitBtn) authSubmitBtn.textContent = "Войти";
  });

  tabRegister?.addEventListener("click", () => {
    authMode = "register";
    tabRegister.className = "btn-primary";
    if (tabLogin) tabLogin.className = "btn-glass";
    nickWrap?.classList.remove("hidden");
    if (authSubmitBtn) authSubmitBtn.textContent = "Создать аккаунт";
  });

  // Login / Register submit
  $("auth-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const supabase = getSupabaseClient();
    if (!supabase) return;

    const email = (($("auth-email") as HTMLInputElement | null)?.value ?? "").trim().toLowerCase();
    const password = ($("auth-password") as HTMLInputElement | null)?.value ?? "";
    const nick = (($("reg-nick") as HTMLInputElement | null)?.value ?? "").trim();

    if (!email.includes("@") || password.length < 6) {
      showBanner(alertEl, "Введите корректный email и пароль (от 6 символов)", "error");
      return;
    }
    if (authMode === "register" && !/^[A-Za-z0-9_]{3,16}$/.test(nick)) {
      showBanner(alertEl, "Ник: 3–16 латинских букв, цифр или _", "error");
      return;
    }

    if (authSubmitBtn) authSubmitBtn.disabled = true;
    try {
      const guard = await invokeEdge<{ ok: boolean }>("auth-guard", {
        action: authMode,
        identifier: email,
        turnstileToken: turnstileToken || "dev-token-placeholder",
      });
      if (!guard.ok) {
        showBanner(alertEl, guard.error ?? "Проверка безопасности не пройдена", "error");
        authTurnstile.reset();
        return;
      }

      if (authMode === "login") {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) {
          showBanner(alertEl, "Неверный email/пароль или email не подтверждён", "error");
          authTurnstile.reset();
          return;
        }
        await loadProfile();
        if (activeHandoff) {
          await sendSessionToLauncher();
        }
      } else {
        const redirectUrl = new URL("./profile.html", window.location.href).toString();
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { mc_nickname: nick },
            emailRedirectTo: redirectUrl,
          },
        });
        if (error) {
          const msg = error.message.toLowerCase();
          let friendly = "Не удалось зарегистрироваться. Проверьте данные или войдите.";
          if (msg.includes("already registered") || msg.includes("already exists")) {
            friendly = "Этот email уже зарегистрирован — перейдите на вкладку «Вход».";
          } else if (msg.includes("rate limit")) {
            friendly = "Лимит отправки писем Supabase исчерпан. Подождите или отключите Confirm Email в Auth настроек.";
          } else if (msg.includes("password")) {
            friendly = "Пароль не соответствует требованиям безопасности (минимум 6–8 символов).";
          }
          showBanner(alertEl, friendly, "error");
          authTurnstile.reset();
          return;
        }
        if (data.session) {
          await loadProfile();
          if (activeHandoff) {
            await sendSessionToLauncher();
          }
        } else {
          showBanner(alertEl, "Письмо подтверждения отправлено на указанный email.", "success");
        }
      }
    } finally {
      if (authSubmitBtn) authSubmitBtn.disabled = false;
    }
  });

  // Save minimal profile
  $("profile-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const supabase = getSupabaseClient();
    if (!supabase) return;
    const { data: userRes } = await supabase.auth.getUser();
    if (!userRes.user) return;

    const nick = (($("edit-nick") as HTMLInputElement | null)?.value ?? "").trim();
    if (!/^[A-Za-z0-9_]{3,16}$/.test(nick)) {
      showBanner(alertEl, "Ник: 3–16 латинских букв, цифр или _", "error");
      return;
    }

    const { error } = await supabase
      .from("profiles")
      .update({ mc_nickname: nick })
      .eq("id", userRes.user.id);

    if (error) {
      showBanner(alertEl, "Не удалось сохранить ник", "error");
      return;
    }
    showBanner(alertEl, "Профиль обновлён", "success");
    await loadProfile();
  });

  // Redeem key
  $("redeem-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    const supabase = getSupabaseClient();
    if (!supabase) return;

    const keyInput = $("license-key-input") as HTMLInputElement | null;
    const cleanKey = (keyInput?.value ?? "").trim().toUpperCase();
    if (!/^[A-Z0-9-]{8,64}$/.test(cleanKey)) {
      showBanner(alertEl, "Проверьте формат лицензионного ключа", "error");
      return;
    }

    const { data: sess } = await supabase.auth.getSession();
    const token = sess.session?.access_token;
    if (!token) return;

    const btn = $("btn-redeem") as HTMLButtonElement | null;
    if (btn) btn.disabled = true;
    try {
      const res = await invokeEdge<{ type: string; until: string }>(
        "redeem-key",
        { key: cleanKey, turnstileToken: turnstileToken || undefined },
        { accessToken: token },
      );
      if (!res.ok) {
        showBanner(alertEl, res.error ?? "Ошибка активации ключа", "error");
        redeemTurnstile.reset();
        return;
      }
      if (keyInput) keyInput.value = "";
      showBanner(
        alertEl,
        res.data?.type === "reset"
          ? "Привязка HWID сброшена"
          : `Лицензия активирована (${res.data?.until ?? "Активна"})`,
        "success",
      );
      await loadProfile();
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  // Platform switcher & download
  document.querySelectorAll<HTMLButtonElement>("[data-dl-platform]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const plat = btn.dataset.dlPlatform as "windows" | "macos" | "linux";
      selectedPlatform = plat;
      document.querySelectorAll<HTMLButtonElement>("[data-dl-platform]").forEach((b) => {
        b.className = b === btn ? "btn-primary" : "btn-glass";
      });
      renderReleaseBox();
    });
  });

  $("btn-copy-sha")?.addEventListener("click", () => {
    const sha = $("release-sha-text")?.textContent ?? "";
    if (sha) void navigator.clipboard?.writeText(sha);
  });

  $("btn-download-launcher")?.addEventListener("click", async () => {
    hideBanner(alertEl);
    const supabase = getSupabaseClient();
    if (!supabase) return;
    const { data: sess } = await supabase.auth.getSession();
    const token = sess.session?.access_token;
    if (!token) return;

    const releaseId = ($("release-select") as HTMLSelectElement | null)?.value || undefined;
    const btn = $("btn-download-launcher") as HTMLButtonElement | null;
    if (btn) btn.disabled = true;

    try {
      const res = await invokeEdge<DownloadResp>(
        "download-release",
        {
          platform: selectedPlatform,
          releaseId,
          turnstileToken: turnstileToken || undefined,
        },
        { accessToken: token },
      );

      if (!res.ok || !res.data?.url) {
        showBanner(alertEl, res.error ?? "Не удалось получить ссылку", "error");
        return;
      }

      const dlLink = $("signed-download-link") as HTMLAnchorElement | null;
      if (dlLink) {
        dlLink.href = res.data.url;
        dlLink.download = res.data.release.file_name;
        dlLink.textContent = `Прямая ссылка (действует ${res.data.expires_in} сек)`;
        dlLink.classList.remove("hidden");
      }

      const tmp = document.createElement("a");
      tmp.href = res.data.url;
      tmp.download = res.data.release.file_name;
      tmp.rel = "noopener noreferrer";
      document.body.appendChild(tmp);
      tmp.click();
      tmp.remove();
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  $("btn-logout")?.addEventListener("click", async () => {
    const supabase = getSupabaseClient();
    if (!supabase) return;
    await supabase.auth.signOut({ scope: "global" });
    await loadProfile();
  });

  void loadProfile();
});
