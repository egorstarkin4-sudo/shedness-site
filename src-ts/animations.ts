// Smooth UI, scroll-reveal, launcher tab, dropdown, and page transitions powered by anime.js v3.2.2
export {};

interface AnimeInstance {
  (params: Record<string, unknown>): unknown;
  stagger: (val: number | [number, number], opts?: Record<string, unknown>) => unknown;
  remove: (targets: unknown) => void;
}

declare global {
  interface Window {
    anime?: AnimeInstance;
  }
}

function getAnime(): AnimeInstance | null {
  if (typeof window === "undefined") return null;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return null;
  return typeof window.anime === "function" ? window.anime : null;
}

function animatePageEntrance(anime: AnimeInstance): void {
  const heroTargets = document.querySelectorAll(
    ".hero .pill-tag, .hero .hero-title, .hero .hero-sub, .hero .hero-cta-row, #preview",
  );
  if (heroTargets.length > 0) {
    anime({
      targets: heroTargets,
      opacity: [0, 1],
      translateY: [18, 0],
      delay: anime.stagger(70, { start: 40 }),
      duration: 620,
      easing: "easeOutExpo",
    });
    return;
  }

  const pageCards = document.querySelectorAll("main > .glass-card, main > section > .glass-card");
  if (pageCards.length > 0) {
    anime({
      targets: pageCards,
      opacity: [0, 1],
      translateY: [14, 0],
      delay: anime.stagger(55),
      duration: 500,
      easing: "easeOutCubic",
    });
  }
}

function initScrollReveals(anime: AnimeInstance): void {
  const sections = document.querySelectorAll<HTMLElement>(".section");
  if (sections.length === 0 || typeof IntersectionObserver !== "function") return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const section = entry.target as HTMLElement;
        observer.unobserve(section);

        const targets = section.querySelectorAll(".section-head, .glass-card");
        if (targets.length === 0) return;

        anime({
          targets,
          opacity: [0, 1],
          translateY: [20, 0],
          delay: anime.stagger(65),
          duration: 580,
          easing: "easeOutExpo",
        });
      });
    },
    { threshold: 0.12 },
  );

  sections.forEach((sec) => {
    const rect = sec.getBoundingClientRect();
    if (rect.top > window.innerHeight * 0.9) {
      sec.querySelectorAll<HTMLElement>(".section-head, .glass-card").forEach((el) => {
        el.style.opacity = "0";
      });
      observer.observe(sec);
    }
  });
}

function initLauncherTabAnimations(anime: AnimeInstance): void {
  document.querySelectorAll<HTMLButtonElement>("[data-launcher-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.launcherTab;
      const view = document.querySelector<HTMLElement>(`[data-launcher-view="${target}"]`);
      if (!view) return;
      const cards = view.querySelectorAll(".glass-subcard");
      if (cards.length === 0) return;

      anime.remove(cards);
      anime({
        targets: cards,
        opacity: [0, 1],
        translateY: [10, 0],
        delay: anime.stagger(45),
        duration: 300,
        easing: "easeOutCubic",
      });
    });
  });

  document.querySelectorAll<HTMLButtonElement>("[data-loader-choice]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pill = document.getElementById("preview-loader-pill");
      if (!pill) return;
      anime.remove(pill);
      anime({
        targets: pill,
        scale: [0.9, 1],
        opacity: [0.5, 1],
        duration: 240,
        easing: "easeOutBack",
      });
    });
  });
}

function initFaqAnimations(anime: AnimeInstance): void {
  document.querySelectorAll<HTMLButtonElement>(".faq-trigger").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".faq-item");
      const answer = item?.querySelector<HTMLElement>(".faq-answer");
      if (!item || !answer) return;
      window.requestAnimationFrame(() => {
        if (item.classList.contains("open")) {
          anime.remove(answer);
          anime({
            targets: answer,
            opacity: [0, 1],
            translateY: [-6, 0],
            duration: 260,
            easing: "easeOutCubic",
          });
        }
      });
    });
  });
}

function initDynamicPopupAnimations(anime: AnimeInstance): void {
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((m) => {
      if (m.type !== "attributes" || m.attributeName !== "class") return;
      const el = m.target as HTMLElement;
      const isMenu = el.classList.contains("c-select-menu");
      const isAlert = el.classList.contains("alert-banner");
      const isDash = el.id === "dashboard-section" || el.id === "admin-console";

      if (!el.classList.contains("hidden")) {
        if (isMenu) {
          anime.remove(el);
          anime({
            targets: el,
            opacity: [0, 1],
            translateY: [-6, 0],
            scale: [0.97, 1],
            duration: 180,
            easing: "easeOutCubic",
          });
        } else if (isAlert) {
          anime.remove(el);
          anime({
            targets: el,
            opacity: [0, 1],
            translateY: [-8, 0],
            duration: 240,
            easing: "easeOutCubic",
          });
        } else if (isDash) {
          const cards = el.querySelectorAll(".glass-card");
          if (cards.length > 0) {
            anime.remove(cards);
            anime({
              targets: cards,
              opacity: [0, 1],
              translateY: [14, 0],
              delay: anime.stagger(55),
              duration: 420,
              easing: "easeOutExpo",
            });
          }
        }
      }
    });
  });

  observer.observe(document.body, {
    subtree: true,
    attributes: true,
    attributeFilter: ["class"],
  });
}

function initPageTransitions(anime: AnimeInstance): void {
  const content = document.querySelector<HTMLElement>(".site-content");
  if (!content) return;

  window.addEventListener("pageshow", () => {
    content.style.opacity = "1";
  });

  document.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
      return;
    }
    const anchor = (e.target as HTMLElement | null)?.closest("a");
    if (!anchor) return;
    if (anchor.hasAttribute("download") || anchor.target === "_blank") return;

    const href = anchor.getAttribute("href") ?? "";
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
      return;
    }

    let dest: URL;
    try {
      dest = new URL(anchor.href, window.location.href);
    } catch {
      return;
    }
    if (dest.origin !== window.location.origin) return;
    if (dest.pathname === window.location.pathname && dest.hash) return;

    e.preventDefault();
    anime({
      targets: content,
      opacity: [1, 0],
      duration: 150,
      easing: "easeInQuad",
      complete: () => {
        window.location.href = dest.toString();
      },
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const anime = getAnime();
  if (!anime) return;

  animatePageEntrance(anime);
  initScrollReveals(anime);
  initLauncherTabAnimations(anime);
  initFaqAnimations(anime);
  initDynamicPopupAnimations(anime);
  initPageTransitions(anime);
});
