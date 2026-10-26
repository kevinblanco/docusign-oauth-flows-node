// Every page: live countdowns for the two-minute authorization code.
const tick = () => {
  for (const el of document.querySelectorAll("[data-until]")) {
    const left = Math.max(0, Math.ceil((Number(el.dataset.until) - Date.now()) / 1000));
    el.textContent = left ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")} left` : "expired";
    el.classList.toggle("expired", !left);
  }
};
tick();
setInterval(tick, 250);
