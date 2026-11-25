import { getSupabaseClient } from "./api";

interface PublicRelease {
  id: string;
  version: string;
  platform: string;
  channel: string;
  file_name: string;
  file_size: number;
  sha256: string;
  min_os: string;
}

function initLauncherTabs(): void {
  const navBtns = document.querySelectorAll<HTMLButtonElement>("[data-launcher-tab]");
  const views = document.querySelectorAll<HTMLElement>("[data-launcher-view]");

  navBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.launcherTab;
      navBtns.forEach((b) => b.classList.toggle("active", b === btn));
      views.forEach((v) => v.classList.toggle("active", v.dataset.launcherView === target));
    });
  });

  const loaderBtns = document.querySelectorAll<HTMLButtonElement>("[data-loader-choice]");
  const loaderPill = document.getElementById("preview-loader-pill");
  const consoleLine = document.getElementById("preview-console-line");

  loaderBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const val = btn.dataset.loaderChoice ?? "fabric";
      loaderBtns.forEach((b) => b.classList.toggle("active", b === btn));
      if (loaderPill) loaderPill.textContent = val.toUpperCase();
      if (consoleLine) consoleLine.textContent = `[Shedness] Профиль ${val} 1.21.4 готов к запуску`;
    });
  });
}

function initFaq(): void {
  document.querySelectorAll<HTMLButtonElement>(".faq-trigger").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".faq-item");
      if (!item) return;
      const isOpen = item.classList.contains("open");
      document.querySelectorAll(".faq-item").forEach((other) => other.classList.remove("open"));
      if (!isOpen) item.classList.add("open");
    });
  });
}

async function initAuthHeaderAndReleases(): Promise<void> {
  const supabase = getSupabaseClient();
  if (!supabase) return;

  const { data: userRes } = await supabase.auth.getUser();
  const profileBtnText = document.getElementById("nav-account-label");
  if (profileBtnText && userRes.user) {
    profileBtnText.textContent = "Кабинет";
  }

  const listEl = document.getElementById("public-releases-list");
  if (!listEl) return;

  const { data: releases } = await supabase.rpc("get_public_releases");
  if (!Array.isArray(releases) || releases.length === 0) return;

  listEl.replaceChildren();
  (releases as PublicRelease[]).slice(0, 4).forEach((rel) => {
    const card = document.createElement("div");
    card.className = "glass-subcard";

    const top = document.createElement("div");
    top.style.display = "flex";
    top.style.justifyContent = "space-between";
    top.style.marginBottom = "6px";

    const title = document.createElement("strong");
    title.style.fontSize = "14.5px";
    title.textContent = `v${rel.version} • ${rel.platform.toUpperCase()}`;

    const badge = document.createElement("span");
    badge.className = "pill-tag";
    badge.style.marginBottom = "0";
    badge.textContent = `${rel.channel} • ${(rel.file_size / (1024 * 1024)).toFixed(1)} MB`;

    top.append(title, badge);

    const meta = document.createElement("div");
    meta.style.fontSize = "12.5px";
    meta.style.color = "var(--text-secondary)";
    meta.style.marginBottom = "6px";
    meta.textContent = `${rel.file_name} • ${rel.min_os}`;

    const sha = document.createElement("div");
    sha.style.fontSize = "11.5px";
    sha.style.color = "#A3E635";
    sha.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, monospace";
    sha.style.wordBreak = "break-all";
    sha.textContent = `SHA256: ${rel.sha256}`;

    card.append(top, meta, sha);
    listEl.appendChild(card);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initLauncherTabs();
  initFaq();
  void initAuthHeaderAndReleases();
});
