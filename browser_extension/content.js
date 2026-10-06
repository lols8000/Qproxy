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

  const VISIBLE_AD_MARKERS = [
    ".ytp-ad-player-overlay",
    ".ytp-ad-preview-container",
    ".ytp-ad-text",
    ".ytp-ad-image-overlay"
  ];

  const state = {
    adActive: false,
    saved: null,
    lastSkipAt: 0,
    sweepScheduled: false
  };

  function isVisible(element) {
    if (!(element instanceof HTMLElement)) return false;
    const style = getComputedStyle(element);
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function firstVisible(selectors) {
    for (const selector of selectors) {
      for (const element of document.querySelectorAll(selector)) {
        if (!isVisible(element) || element.hasAttribute("disabled")) continue;
        return element;
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

    return VISIBLE_AD_MARKERS.some((selector) =>
      Array.from(document.querySelectorAll(selector)).some(isVisible)
    );
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
    let skipped = false;
    if (now - state.lastSkipAt > 250) {
      skipped = clickIfPresent(SKIP_SELECTORS);
      if (skipped) state.lastSkipAt = now;
    }

    clickIfPresent(CLOSE_SELECTORS);

    // Give a real skip button one cycle to finish the transition before
    // touching the video element itself.
    if (skipped) return;

    const video =
      document.querySelector("video.html5-main-video") ||
      document.querySelector("#movie_player video") ||
      document.querySelector("video");

    if (video instanceof HTMLVideoElement) {
      shortenAd(video);
    }
  }

  function scheduleSweep() {
    if (state.sweepScheduled) return;
    state.sweepScheduled = true;
    requestAnimationFrame(() => {
      state.sweepScheduled = false;
      sweep();
    });
  }

  function start() {
    const root = document.documentElement;
    if (!root) {
      setTimeout(start, 25);
      return;
    }

    const observer = new MutationObserver(scheduleSweep);
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
