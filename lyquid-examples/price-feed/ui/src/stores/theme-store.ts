import { create } from "zustand";

export type ThemeMode = "light" | "dark";
export type ThemeName = "oracle";

type ThemeState = {
  mode: ThemeMode;
  theme: ThemeMode;
  themeName: ThemeName;
  setTheme: (mode: ThemeMode) => void;
  toggleTheme: (mode?: ThemeMode) => void;
  restore: () => void;
};

const storageKey = "price-feed-theme";

function applyTheme(mode: ThemeMode) {
  document.documentElement.classList.toggle("dark", mode === "dark");
  document.documentElement.classList.toggle("light", mode === "light");
}

function readStoredTheme(): ThemeMode {
  return window.localStorage.getItem(storageKey) === "light" ? "light" : "dark";
}

export const useThemeStore = create<ThemeState>((set, get) => ({
  mode: "dark",
  theme: "dark",
  themeName: "oracle",
  setTheme: (mode) => {
    applyTheme(mode);
    window.localStorage.setItem(storageKey, mode);
    set({ mode, theme: mode });
  },
  toggleTheme: (mode) => {
    get().setTheme(mode ?? (get().mode === "light" ? "dark" : "light"));
  },
  restore: () => {
    get().setTheme(readStoredTheme());
  },
}));
