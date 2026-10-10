(() => {
  "use strict";

  const SKIP_SELECTORS = [
    "button.ytp-ad-skip-button-modern",
    "button.ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    "button[class*='ytp-ad-skip']"
  ];
  const CLOSE_SELECTORS = [
    ".ytp-ad-overlay-close-button",
    ".ytp-ad-overlay-close-container button"
  ];

  const state = {
    saved: null,
    adStartedAt: 0,
    lastSkipAt: 0,
    seekedVideo: null
  };

  function visibleButton(selectors) {
    const player = document.querySelector("#movie_player");
    if (!player) return null;
    for (const selector of selectors) {
      for (const element of player.querySelectorAll(selector)) {
        if (!(element instanceof HTMLElement) || element.hasAttribute("disabled")) continue;
        const style = getComputedStyle(element);
        const bounds = element.getBoundingClientRect();
        if (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          bounds.width > 0 &&
          bounds.height > 0
        ) return element;
      }
    }
    return null;
  }

  function adIsPlaying(player) {
    // Do not infer "ad playing" from a generic/hidden DOM container.
    // YouTube leaves ad containers mounted outside advertising periods.
    return player && (
      player.classList.contains("ad-showing") ||
      player.classList.contains("ad-interrupting")
    );
  }

  function restore() {
    const saved = state.saved;
    state.saved = null;
    state.adStartedAt = 0;
    state.seekedVideo = null;
    if (!saved || !saved.video.isConnected) return;
    try {
      saved.video.muted = saved.muted;
      saved.video.volume = saved.volume;
      saved.video.playbackRate = saved.playbackRate;
    } catch {
      // Player can be replaced during YouTube SPA navigation.
    }
  }

  function shortenActiveAd(video) {
    if (state.saved && state.saved.video !== video) restore();
    if (!state.saved) {
      state.saved = {
        video,
        muted: video.muted,
        volume: video.volume,
        playbackRate: video.playbackRate
      };
    }
    try { video.muted = true; } catch {}
    // 4x is supported much more consistently than 16x on Firefox/Chromium.
    try { video.playbackRate = 4; } catch {}

    const elapsed = Date.now() - state.adStartedAt;
    const duration = Number(video.duration);
    const position = Number(video.currentTime);
    if (
      elapsed > 900 &&
      state.seekedVideo !== video &&
      Number.isFinite(duration) &&
      duration >= 5 &&
      duration <= 90 &&
      Number.isFinite(position) &&
      position < duration - 1
    ) {
      try {
        video.currentTime = duration - 0.25;
        state.seekedVideo = video;
      } catch {}
    }
  }

  function sweep() {
    const player = document.querySelector("#movie_player");
    if (!adIsPlaying(player)) {
      if (state.saved || state.adStartedAt) restore();
      return;
    }

    if (!state.adStartedAt) state.adStartedAt = Date.now();
    const now = Date.now();
    const skip = visibleButton(SKIP_SELECTORS);
    if (skip && now - state.lastSkipAt > 350) {
      state.lastSkipAt = now;
      try { skip.click(); } catch {}
      return;
    }
    const close = visibleButton(CLOSE_SELECTORS);
    if (close) {
      try { close.click(); } catch {}
    }

    // Never touch media outside the confirmed YouTube player.
    const video = player.querySelector("video.html5-main-video");
    if (video instanceof HTMLVideoElement) shortenActiveAd(video);
  }

  // A single bounded interval avoids observing every DOM/style mutation of
  // YouTube, which previously could cause excessive work and visual stutter.
  setInterval(sweep, 450);
  sweep();
})();
