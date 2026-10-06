(() => {
  "use strict";

  const SKIP_SELECTORS = [
    "button.ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button-modern",
    ".ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    "button[class*='ytp-ad-skip']",
    "button[class*='skip-ad']"
  ];

  const CLOSE_SELECTORS = [
    ".ytp-ad-overlay-close-button",
    ".ytp-ad-overlay-close-container button",
    "button[aria-label*='Fechar']",
    "button[aria-label*='Close']"
  ];

  const AD_MARKERS = [
    ".ad-showing",
    ".ad-interrupting",
    ".ytp-ad-player-overlay",
    ".ytp-ad-module"
  ];

  const state = {
    adActive: false,
    saved: null,
    lastSkipAt: 0
  };

  function firstVisible(selectors) {
    for (const selector of selectors) {
      for (const element of document.querySelectorAll(selector)) {
        if (!(element instanceof HTMLElement)) continue;
        const style = getComputedStyle(element);
        if (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          !element.hasAttribute("disabled")
        ) {
          return element;
        }
      }
    }
    return null;
  }

  function clickIfPresent(selectors) {
    const element = firstVisible(selectors);
    if (!element) return false;
    try {
      element.click();
      return true;
    } catch {
      return false;
    }
  }

  function playerIsAdvertising() {
    const player = document.querySelector("#movie_player");
    if (
      player &&
      (player.classList.contains("ad-showing") ||
        player.classList.contains("ad-interrupting"))
    ) {
      return true;
    }

    return AD_MARKERS.some((selector) => document.querySelector(selector));
  }

  function rememberVideo(video) {
    if (state.saved) return;
    state.saved = {
      video,
      muted: video.muted,
      volume: video.volume,
      playbackRate: video.playbackRate
    };
  }

  function restoreVideo() {
    const saved = state.saved;
    state.saved = null;
    state.adActive = false;

    if (!saved || !saved.video || !saved.video.isConnected) return;

    try {
      saved.video.muted = saved.muted;
      saved.video.volume = saved.volume;
      saved.video.playbackRate = saved.playbackRate;
    } catch {
      // YouTube may replace the video element during navigation.
    }
  }

  function shortenAd(video) {
    rememberVideo(video);

    try {
      video.muted = true;
    } catch {}

    try {
      video.playbackRate = 16;
    } catch {}

    const duration = Number(video.duration);
    const current = Number(video.currentTime);

    if (
      Number.isFinite(duration) &&
      duration > 0.3 &&
      Number.isFinite(current) &&
      duration - current > 0.25
    ) {
      try {
        video.currentTime = Math.max(current, duration - 0.08);
      } catch {}
    }

    if (video.paused) {
      try {
        const promise = video.play();
        if (promise && typeof promise.catch === "function") {
          promise.catch(() => {});
        }
      } catch {}
    }
  }

  function sweep() {
    const advertising = playerIsAdvertising();

    if (!advertising) {
      if (state.adActive) restoreVideo();
      return;
    }

    state.adActive = true;

    const now = Date.now();
    if (now - state.lastSkipAt > 250) {
      if (clickIfPresent(SKIP_SELECTORS)) {
        state.lastSkipAt = now;
      }
    }

    clickIfPresent(CLOSE_SELECTORS);

    const video =
      document.querySelector("video.html5-main-video") ||
      document.querySelector("#movie_player video") ||
      document.querySelector("video");

    if (video instanceof HTMLVideoElement) {
      shortenAd(video);
    }
  }

  function start() {
    const root = document.documentElement;
    if (!root) {
      setTimeout(start, 25);
      return;
    }

    const observer = new MutationObserver(() => sweep());
    observer.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class", "style", "aria-label"]
    });

    setInterval(sweep, 300);
    sweep();
  }

  start();
})();
