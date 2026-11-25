import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { getSiteConfig, isSupabaseConfigured } from "./config";

let client: SupabaseClient | null = null;

export function getSupabaseClient(): SupabaseClient | null {
  if (!isSupabaseConfigured()) return null;
  if (!client) {
    const cfg = getSiteConfig();
    client = createClient(cfg.supabaseUrl, cfg.supabaseAnonKey);
  }
  return client;
}

export interface EdgeResult<T> {
  ok: boolean;
  data?: T;
  error?: string;
  status: number;
}

export async function invokeEdge<T>(
  fnName: string,
  body: Record<string, unknown>,
  options?: {
    accessToken?: string;
    adminSessionToken?: string;
    timeoutMs?: number;
  },
): Promise<EdgeResult<T>> {
  const cfg = getSiteConfig();
  if (!isSupabaseConfigured()) {
    return { ok: false, error: "Supabase не настроен в assets/js/site-config.js", status: 503 };
  }

  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), options?.timeoutMs ?? 12_000);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      apikey: cfg.supabaseAnonKey,
      "x-requested-with": "ShednessWebClient",
    };

    if (options?.accessToken) {
      headers.Authorization = `Bearer ${options.accessToken}`;
    }
    if (options?.adminSessionToken) {
      headers["x-admin-session"] = options.adminSessionToken;
    }

    const res = await fetch(`${cfg.supabaseUrl}/functions/v1/${fnName}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      cache: "no-store",
    });

    const json = (await res.json().catch(() => null)) as (T & { ok?: boolean; error?: string }) | null;
    if (!res.ok || !json?.ok) {
      return {
        ok: false,
        error: json?.error ?? `Ошибка сервера (${res.status})`,
        status: res.status,
      };
    }
    return { ok: true, data: json, status: res.status };
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      return { ok: false, error: "Превышено время ожидания сервера", status: 504 };
    }
    return { ok: false, error: "Сетевая ошибка при обращении к серверу", status: 502 };
  } finally {
    window.clearTimeout(timer);
  }
}

export function showBanner(el: HTMLElement | null, text: string, type: "error" | "success"): void {
  if (!el) return;
  el.textContent = text;
  el.className = `alert-banner ${type === "error" ? "alert-error" : "alert-success"}`;
  el.classList.remove("hidden");
}

export function hideBanner(el: HTMLElement | null): void {
  if (!el) return;
  el.textContent = "";
  el.classList.add("hidden");
}

export function mountTurnstile(
  container: HTMLElement | null,
  onToken: (token: string) => void,
): { reset: () => void } {
  const cfg = getSiteConfig();
  if (!container) return { reset: () => {} };

  if (!cfg.turnstileSiteKey) {
    container.textContent = "Cloudflare Turnstile: ключ не задан (dev)";
    container.style.fontSize = "12px";
    container.style.color = "#8E8E98";
    return { reset: () => {} };
  }

  let widgetId: string | undefined;

  const tryRender = () => {
    if (!window.turnstile || widgetId) return;
    widgetId = window.turnstile.render(container, {
      sitekey: cfg.turnstileSiteKey,
      theme: "dark",
      callback: (t) => onToken(t),
      "expired-callback": () => onToken(""),
      "error-callback": () => onToken(""),
    });
  };

  if (window.turnstile) {
    tryRender();
  } else {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = tryRender;
    document.head.appendChild(script);
  }

  return {
    reset: () => {
      if (widgetId && window.turnstile) {
        window.turnstile.reset(widgetId);
      }
      onToken("");
    },
  };
}
