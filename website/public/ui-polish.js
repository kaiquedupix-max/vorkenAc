(() => {
  const preferenceKey = "vorken-ui-sound";
  const storedPreference = localStorage.getItem(preferenceKey);
  let soundEnabled = storedPreference !== "off";
  let audioContext = null;

  function playClick(tone = 520) {
    if (!soundEnabled || !window.AudioContext && !window.webkitAudioContext) return;

    try {
      const AudioEngine = window.AudioContext || window.webkitAudioContext;
      audioContext ||= new AudioEngine();
      const oscillator = audioContext.createOscillator();
      const gain = audioContext.createGain();
      const now = audioContext.currentTime;

      oscillator.type = "sine";
      oscillator.frequency.setValueAtTime(tone, now);
      oscillator.frequency.exponentialRampToValueAtTime(tone * 0.82, now + 0.045);
      gain.gain.setValueAtTime(0.0001, now);
      gain.gain.exponentialRampToValueAtTime(0.025, now + 0.006);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.05);
      oscillator.connect(gain);
      gain.connect(audioContext.destination);
      oscillator.start(now);
      oscillator.stop(now + 0.055);
    } catch {
      // Sound is optional; blocked audio must never affect navigation.
    }
  }

  function updateSoundToggle() {
    const toggle = document.getElementById("adminSoundToggle");
    if (!toggle) return;
    toggle.textContent = soundEnabled ? "♪" : "♩";
    toggle.classList.toggle("is-muted", !soundEnabled);
    toggle.setAttribute("aria-pressed", String(soundEnabled));
    toggle.setAttribute("aria-label", soundEnabled ? "Desativar sons da interface" : "Ativar sons da interface");
    toggle.title = toggle.getAttribute("aria-label");
  }

  document.addEventListener("pointerdown", (event) => {
    const target = event.target.closest("button, .button, .report-category-card, .feature-card, .confidence-card");
    if (!target || target.disabled) return;

    const bounds = target.getBoundingClientRect();
    const ripple = document.createElement("span");
    ripple.className = "ui-ripple";
    ripple.style.left = `${event.clientX - bounds.left}px`;
    ripple.style.top = `${event.clientY - bounds.top}px`;
    target.appendChild(ripple);
    ripple.addEventListener("animationend", () => ripple.remove(), { once: true });
  });

  document.addEventListener("click", (event) => {
    const soundToggle = event.target.closest("#adminSoundToggle");
    if (soundToggle) {
      soundEnabled = !soundEnabled;
      localStorage.setItem(preferenceKey, soundEnabled ? "on" : "off");
      updateSoundToggle();
      if (soundEnabled) playClick(660);
      return;
    }

    if (event.target.closest("button, a.button, .vorken-nav-button, .report-category-card")) {
      playClick();
    }
  });

  updateSoundToggle();
})();
