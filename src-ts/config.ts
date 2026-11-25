export interface PublicSiteConfig {
  supabaseUrl: string;
  supabaseAnonKey: string;
  turnstileSiteKey: string;
}

declare global {
  interface Window {
    __SHEDNESS_CONFIG__?: Partial<PublicSiteConfig>;
    turnstile?: {
      render: (
        el: HTMLElement,
        opts: {
          sitekey: string;
          theme?: "dark" | "light" | "auto";
          callback?: (token: string) => void;
          "expired-callback"?: () => void;
          "error-callback"?: () => void;
        },
      ) => string;
      reset: (widgetId?: string) => void;
    };
  }
}

export function getSiteConfig(): PublicSiteConfig {
  const raw = (typeof window !== "undefined" ? window.__SHEDNESS_CONFIG__ : undefined) ?? {};
  const cleanUrl = String(raw.supabaseUrl ?? "")
    .trim()
    .replace(/\/rest\/v1\/?$/, "")
    .replace(/\/$/, "");
  return {
    supabaseUrl: cleanUrl,
    supabaseAnonKey: String(raw.supabaseAnonKey ?? "").trim(),
    turnstileSiteKey: String(raw.turnstileSiteKey ?? "").trim(),
  };
}

export function isSupabaseConfigured(): boolean {
  const cfg = getSiteConfig();
  const validProto =
    cfg.supabaseUrl.startsWith("https://") ||
    cfg.supabaseUrl.startsWith("http://127.0.0.1") ||
    cfg.supabaseUrl.startsWith("http://localhost");
  return Boolean(
    validProto &&
      cfg.supabaseAnonKey.length > 20 &&
      !cfg.supabaseUrl.includes("YOUR_PROJECT_REF"),
  );
}
