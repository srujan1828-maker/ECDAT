"use client";
import { useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";

function subscribe(listener: () => void) {
  window.addEventListener("ecdat-theme", listener);
  return () => window.removeEventListener("ecdat-theme", listener);
}
function snapshot() {
  return document.documentElement.classList.contains("dark");
}
export function ThemeToggle() {
  const dark = useSyncExternalStore(subscribe, snapshot, () => false);
  function toggle() {
    const next = !snapshot();
    document.documentElement.classList.toggle("dark", next);
    try {
      localStorage.setItem("ecdat-theme-v2", next ? "dark" : "light");
    } catch {
      // Theme still works when browser storage is unavailable.
    }
    window.dispatchEvent(new Event("ecdat-theme"));
  }
  return (
    <button
      className="ec-button secondary theme-toggle"
      onClick={toggle}
      aria-label={`Switch to ${dark ? "light" : "dark"} mode`}
      title={`Switch to ${dark ? "light" : "dark"} mode`}
    >
      {dark ? <Sun size={16} /> : <Moon size={16} />}
      <span>{dark ? "Light" : "Dark"} mode</span>
    </button>
  );
}
