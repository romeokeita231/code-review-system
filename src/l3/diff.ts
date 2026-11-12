export function addedLines(diff: string | null): Map<string, Set<number>> | null {
  if (diff === null) return null;
  const map = new Map<string, Set<number>>();
  let current: string | null = null;
  let line = 0;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("+++ ")) {
      const target = raw.slice(4).trim();
      current = target === "/dev/null" ? null : target.replace(/^b\//, "");
      if (current !== null && !map.has(current)) map.set(current, new Set());
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk?.[1]) {
      line = Number(hunk[1]);
      continue;
    }
    if (current === null) continue;
    if (raw.startsWith("+")) {
      map.get(current)?.add(line);
      line += 1;
    } else if (raw.startsWith("-") || raw.startsWith("\\")) {
      continue;
    } else {
      line += 1;
    }
  }
  return map;
}

export function repoPath(root: string, path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const base = root.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  if (base.length > 0 && normalized.toLowerCase().startsWith(`${base}/`)) {
    return normalized.slice(base.length + 1);
  }
  return normalized.replace(/^\.\//, "");
}

export function intersectsAdded(
  added: Map<string, Set<number>> | null,
  file: string,
  startLine: number,
  endLine: number,
): boolean {
  if (added === null) return true;
  const lines = added.get(file);
  if (!lines) return false;
  for (let line = startLine; line <= endLine; line += 1) {
    if (lines.has(line)) return true;
  }
  return false;
}
