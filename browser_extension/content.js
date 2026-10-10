(() => {
  "use strict";

  // A extensão só interage com controles explícitos da interface.
  // Não altera HTMLVideoElement (velocidade, posição, áudio ou play/pause).
  const SKIP_SELECTORS = [
    "button.ytp-ad-skip-button-modern",
    "button.ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    "button[class*='ytp-ad-skip']",
    "button[class*='skip-ad']"
  ];
  const CLOSE_SELECTORS = [
    ".ytp-ad-overlay-close-button",
    ".ytp-ad-overlay-close-container button"
  ];

  const RETRY_MS = 1000;
  let lastSkipAt = 0;
  let lastCloseAt = 0;

  function activeAdPlayer() {
    const player = document.querySelector("#movie_player");
    if (!player) return null;
    return (
      player.classList.contains("ad-showing") ||
      player.classList.contains("ad-interrupting")
    ) ? player : null;
  }

  function visibleEnabledControl(player, selectors) {
    for (const selector of selectors) {
      for (const element of player.querySelectorAll(selector)) {
        if (!(element instanceof HTMLElement)) continue;
        if (element.disabled || element.matches("[disabled], [aria-disabled='true']")) continue;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        if (
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          rect.width > 0 &&
          rect.height > 0
        ) return element;
      }
    }
    return null;
  }

  function clickControl(player, selectors, lastAttempt) {
    const now = Date.now();
    if (now - lastAttempt < RETRY_MS) return lastAttempt;
    const control = visibleEnabledControl(player, selectors);
    if (!control) return lastAttempt;
    try {
      control.click();
      return now;
    } catch {
      return lastAttempt;
    }
  }

  function sweep() {
    const player = activeAdPlayer();
    if (!player) return;
    lastSkipAt = clickControl(player, SKIP_SELECTORS, lastSkipAt);
    lastCloseAt = clickControl(player, CLOSE_SELECTORS, lastCloseAt);
  }

  setInterval(sweep, 500);
  sweep();
})();
