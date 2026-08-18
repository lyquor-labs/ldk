import BigNumber from "bignumber.js";

export const getColorVariable = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name);

export function addOklchAlpha(color: string, alpha: number): string {
  const clampedAlpha = Math.min(Math.max(alpha, 0), 1);
  const oklchRegex = /oklch\(\s*([^/)]+?)\s*(?:\/\s*[^)]+)?\)/;

  return oklchRegex.test(color)
    ? color.replace(oklchRegex, `oklch($1 / ${clampedAlpha})`)
    : color;
}

export function shortStr(value: string, padStart: number, padEnd?: number) {
  if (!value) return "";
  const start = value.slice(0, padStart);
  const end = value.slice(-(padEnd || padStart));
  return `${start}...${end}`;
}

export const fmtUsd = (value?: number | null) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return `$${BigNumber(value).toFixed(2, BigNumber.ROUND_DOWN)}`;
};
