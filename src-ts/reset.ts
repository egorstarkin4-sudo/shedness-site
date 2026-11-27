import { getSiteConfig } from "./config";
import { getSupabaseClient, hideBanner, invokeEdge, mountTurnstile, showBanner } from "./api";

document.addEventListener("DOMContentLoaded", () => {
  const supabase = getSupabaseClient();
  const alertEl = document.getElementById("reset-alert");
  const reqForm = document.getElementById("reset-request-form");
  const updForm = document.getElementById("reset-update-form");
  let token = "";

  const resetTurnstile = mountTurnstile(document.getElementById("reset-turnstile"), (t) => {
    token = t;
  });

  if (supabase) {
    supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY") {
        reqForm?.classList.add("hidden");
        updForm?.classList.remove("hidden");
      }
    });
  }

  if (window.location.hash.includes("type=recovery")) {
    reqForm?.classList.add("hidden");
    updForm?.classList.remove("hidden");
  }

  reqForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    if (!supabase) return;

    if (getSiteConfig().turnstileSiteKey && !token) {
      showBanner(alertEl, "Пройдите проверку Cloudflare Turnstile", "error");
      return;
    }

    const email = (document.getElementById("reset-email") as HTMLInputElement | null)?.value.trim() ?? "";
    const guard = await invokeEdge<{ ok: boolean }>("auth-guard", {
      action: "reset",
      identifier: email.toLowerCase(),
      turnstileToken: token || "dev-token-placeholder",
    });
    resetTurnstile.reset();
    if (!guard.ok) {
      showBanner(alertEl, guard.error ?? "Проверка не пройдена", "error");
      return;
    }

    const redirectTo = new URL("./reset-password.html", window.location.href).toString();
    await supabase.auth.resetPasswordForEmail(email, { redirectTo });
    showBanner(alertEl, "Если аккаунт существует, ссылка для сброса отправлена на email.", "success");
  });

  updForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    hideBanner(alertEl);
    if (!supabase) return;

    const pass = (document.getElementById("new-password") as HTMLInputElement | null)?.value ?? "";
    if (pass.length < 8) {
      showBanner(alertEl, "Пароль должен содержать минимум 8 символов", "error");
      return;
    }

    const { error } = await supabase.auth.updateUser({ password: pass });
    if (error) {
      showBanner(alertEl, "Не удалось обновить пароль", "error");
      return;
    }
    showBanner(alertEl, "Пароль обновлён. Можно войти в кабинет.", "success");
  });
});
