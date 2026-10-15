(() => {
  "use strict";

  // Somente controles nativos do YouTube. Nunca escreva no
  // HTMLVideoElement: isso compromete velocidade e reprodução.
  const SKIP_SELECTORS = [
    "button.ytp-ad-skip-button-modern",
    "button.ytp-ad-skip-button",
    ".ytp-skip-ad-button",
    ".ytp-ad-skip-button-container button",
    "button[class*='ytp-ad-skip']"
  ];
  const CLOSE_SELECTORS = [
    ".ytp-ad-overlay-close-button",
    ".ytp-ad-overlay-close-container button"
  ];

  const RETRY_MS = 700;
  let lastSkipAt = 0;
  let lastCloseAt = 0;
  let observedPlayer = null;
  let observer = null;

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
        if (element.matches("[disabled], [aria-disabled='true']")) continue;
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

  function watchPlayer() {
    const player = document.querySelector("#movie_player");
    if (player === observedPlayer) return;
    if (observer) observer.disconnect();
    observedPlayer = player;
    if (!player) return;

    // Observação estreita: só o atributo class do player.
    // Não monitora mutações de toda a página nem altera a mídia.
    observer = new MutationObserver(sweep);
    observer.observe(player, {
      attributes: true,
      attributeFilter: ["class"],
      childList: false,
      subtree: false
    });
    sweep();
  }

  // Em navegação SPA, o YouTube pode substituir o player sem
  // recarregar a página; a observação deve ser reconectada.
  document.addEventListener("yt-navigate-finish", () => {
    watchPlayer();
    sweep();
  });

  setInterval(() => {
    watchPlayer();
    sweep();
  }, 200);

  watchPlayer();
  sweep();
})();
