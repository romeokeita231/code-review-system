import { createHash } from "node:crypto";
import type { MergedFinding, PairingRow } from "../contracts/index.js";

export interface Interval {
  startLine: number;
  endLine: number;
}

export interface GtSpan extends Interval {
  id: string;
  path: string;
  cwe: string | null;
}

interface FindingRecord {
  finding: MergedFinding;
  mergedId: string;
}

interface Edge {
  findingIndex: number;
  overlap: number;
  union: number;
}

function spanSize(interval: Interval): number {
  return Math.max(0, interval.endLine - interval.startLine + 1);
}

function normalizeIntervals(intervals: readonly Interval[]): Array<[number, number]> {
  return intervals
    .map((interval) => {
      const start = Math.min(interval.startLine, interval.endLine);
      const end = Math.max(interval.startLine, interval.endLine);
      return [start, end] as [number, number];
    })
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
}

function mergeIntervals(intervals: readonly Interval[]): Array<[number, number]> {
  const sorted = normalizeIntervals(intervals);
  const merged: Array<[number, number]> = [];
  for (const [start, end] of sorted) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1] + 1) {
      if (end > last[1]) last[1] = end;
    } else {
      merged.push([start, end]);
    }
  }
  return merged;
}

export function lineUnionSize(intervals: readonly Interval[]): number {
  return mergeIntervals(intervals).reduce((sum, [start, end]) => sum + (end - start + 1), 0);
}

export function intersectionSize(a: readonly Interval[], b: readonly Interval[]): number {
  const left = mergeIntervals(a);
  const right = mergeIntervals(b);
  let i = 0;
  let j = 0;
  let total = 0;
  while (i < left.length && j < right.length) {
    const [l0, l1] = left[i]!;
    const [r0, r1] = right[j]!;
    const start = Math.max(l0, r0);
    const end = Math.min(l1, r1);
    if (start <= end) total += end - start + 1;
    if (l1 < r1) i += 1;
    else j += 1;
  }
  return total;
}

export function mergedIdOf(finding: Pick<MergedFinding, "file" | "startLine" | "endLine" | "cwe">): string {
  const key = [
    finding.file,
    String(finding.startLine),
    String(finding.endLine),
    finding.cwe ?? "",
  ].join("\u0000");
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

class UnionFind {
  private readonly parent: number[];

  constructor(size: number) {
    this.parent = Array.from({ length: size }, (_, index) => index);
  }

  find(value: number): number {
    let root = value;
    while (this.parent[root] !== root) root = this.parent[root]!;
    let cursor = value;
    while (this.parent[cursor] !== root) {
      const next = this.parent[cursor]!;
      this.parent[cursor] = root;
      cursor = next;
    }
    return root;
  }

  union(a: number, b: number): void {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA !== rootB) this.parent[rootB] = rootA;
  }
}

function compareGt(a: GtSpan, b: GtSpan): number {
  if (a.path !== b.path) return a.path < b.path ? -1 : 1;
  if (a.startLine !== b.startLine) return a.startLine - b.startLine;
  if (a.endLine !== b.endLine) return a.endLine - b.endLine;
  const left = a.cwe ?? "";
  const right = b.cwe ?? "";
  if (left !== right) return left < right ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function compareFinding(a: FindingRecord, b: FindingRecord): number {
  if (a.finding.file !== b.finding.file) return a.finding.file < b.finding.file ? -1 : 1;
  if (a.finding.startLine !== b.finding.startLine) return a.finding.startLine - b.finding.startLine;
  if (a.finding.endLine !== b.finding.endLine) return a.finding.endLine - b.finding.endLine;
  const left = a.finding.cwe ?? "";
  const right = b.finding.cwe ?? "";
  if (left !== right) return left < right ? -1 : 1;
  return a.mergedId < b.mergedId ? -1 : a.mergedId > b.mergedId ? 1 : 0;
}

function hungarian(cost: bigint[][]): number[] {
  const n = cost.length;
  if (n === 0) return [];
  const u = new Array<bigint>(n + 1).fill(0n);
  const v = new Array<bigint>(n + 1).fill(0n);
  const p = new Array<number>(n + 1).fill(0);
  const way = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= n; i += 1) {
    p[0] = i;
    let j0 = 0;
    const minv = new Array<bigint | null>(n + 1).fill(null);
    const used = new Array<boolean>(n + 1).fill(false);
    do {
      used[j0] = true;
      const i0 = p[j0]!;
      let delta: bigint | null = null;
      let j1 = 0;
      for (let j = 1; j <= n; j += 1) {
        if (used[j]) continue;
        const current = cost[i0 - 1]![j - 1]! - u[i0]! - v[j]!;
        if (minv[j] === null || current < minv[j]!) {
          minv[j] = current;
          way[j] = j0;
        }
        if (delta === null || minv[j]! < delta) {
          delta = minv[j]!;
          j1 = j;
        }
      }
      if (delta === null) break;
      for (let j = 0; j <= n; j += 1) {
        if (used[j]) {
          const row = p[j]!;
          u[row] = u[row]! + delta;
          v[j] = v[j]! - delta;
        } else if (minv[j] !== null) {
          minv[j] = minv[j]! - delta;
        }
      }
      j0 = j1;
    } while (p[j0] !== 0);
    do {
      const previous = way[j0]!;
      p[j0] = p[previous]!;
      j0 = previous;
    } while (j0 !== 0);
  }
  const assignment = new Array<number>(n).fill(-1);
  for (let j = 1; j <= n; j += 1) {
    if (p[j] !== 0) assignment[p[j]! - 1] = j - 1;
  }
  return assignment;
}

export function pair(
  runId: string,
  gts: readonly GtSpan[],
  findings: readonly MergedFinding[],
): PairingRow[] {
  const gtSorted = [...gts].sort(compareGt);
  const findingRecords = findings
    .map((finding) => ({ finding, mergedId: mergedIdOf(finding) }))
    .sort(compareFinding);

  if (gtSorted.length === 0) return [];

  const assigned = new Map<number, Edge>();

  if (findingRecords.length > 0) {
    const gtByPath = new Map<string, number[]>();
    const findingByPath = new Map<string, number[]>();
    gtSorted.forEach((gt, index) => {
      const list = gtByPath.get(gt.path) ?? [];
      list.push(index);
      gtByPath.set(gt.path, list);
    });
    findingRecords.forEach((record, index) => {
      const list = findingByPath.get(record.finding.file) ?? [];
      list.push(index);
      findingByPath.set(record.finding.file, list);
    });

    let maxSpan = 1;
    for (const gt of gtSorted) maxSpan = Math.max(maxSpan, spanSize(gt));
    for (const record of findingRecords) maxSpan = Math.max(maxSpan, spanSize(record.finding));

    const pairsCap = Math.max(1, Math.min(gtSorted.length, findingRecords.length));
    let maxGtPerPath = 0;
    let maxFindingPerPath = 0;
    for (const list of gtByPath.values()) maxGtPerPath = Math.max(maxGtPerPath, list.length);
    for (const list of findingByPath.values()) {
      maxFindingPerPath = Math.max(maxFindingPerPath, list.length);
    }

    const base = BigInt(maxFindingPerPath + 1);
    const powers: bigint[] = [1n];
    for (let exponent = 1; exponent <= maxGtPerPath; exponent += 1) {
      powers.push(powers[exponent - 1]! * base);
    }
    const CANON_CAP = powers[maxGtPerPath]! * base + 1n;
    const UNION_W = CANON_CAP;
    const OVERLAP_W = (BigInt(maxSpan * pairsCap) + 1n) * UNION_W;
    const COUNT_W = (BigInt(maxSpan * pairsCap) + 1n) * OVERLAP_W;
    const INFEASIBLE_COST = COUNT_W * 1_000_000n;

    for (const [path, gtIndices] of gtByPath) {
      const findingIndices = findingByPath.get(path) ?? [];
      if (findingIndices.length === 0) continue;
      const nodes = gtIndices.length + findingIndices.length;
      const dsu = new UnionFind(nodes);
      const edges: Array<{ localGt: number; localFinding: number; overlap: number; union: number }> = [];

      gtIndices.forEach((gtIndex, localGt) => {
        const gt = gtSorted[gtIndex]!;
        findingIndices.forEach((findingIndex, localFinding) => {
          const finding = findingRecords[findingIndex]!.finding;
          const overlap = intersectionSize([gt], [finding]);
          if (overlap <= 0) return;
          const union = spanSize(gt) + spanSize(finding) - overlap;
          edges.push({ localGt, localFinding, overlap, union });
          dsu.union(localGt, gtIndices.length + localFinding);
        });
      });

      if (edges.length === 0) continue;

      const components = new Map<number, { gts: number[]; findings: number[] }>();
      for (let localGt = 0; localGt < gtIndices.length; localGt += 1) {
        const root = dsu.find(localGt);
        const component = components.get(root) ?? { gts: [], findings: [] };
        component.gts.push(localGt);
        components.set(root, component);
      }
      for (let localFinding = 0; localFinding < findingIndices.length; localFinding += 1) {
        const root = dsu.find(gtIndices.length + localFinding);
        const component = components.get(root);
        if (component) component.findings.push(localFinding);
      }

      for (const component of components.values()) {
        if (component.findings.length === 0 || component.gts.length === 0) continue;
        const gtCount = component.gts.length;
        const findingCount = component.findings.length;
        const size = gtCount + findingCount;
        const matrix: bigint[][] = Array.from({ length: size }, () => new Array<bigint>(size).fill(0n));

        component.gts.forEach((localGt, row) => {
          const gtIndex = gtIndices[localGt]!;
          const gt = gtSorted[gtIndex]!;
          const gtRank = localGt;
          component.findings.forEach((localFinding, column) => {
            const findingIndex = findingIndices[localFinding]!;
            const finding = findingRecords[findingIndex]!.finding;
            const overlap = intersectionSize([gt], [finding]);
            if (overlap <= 0) {
              matrix[row]![column] = INFEASIBLE_COST;
              return;
            }
            const union = spanSize(gt) + spanSize(finding) - overlap;
            const exponent = Math.max(0, gtCount - 1 - gtRank);
            const penalty = BigInt(localFinding) * powers[exponent]!;
            const weight =
              COUNT_W +
              OVERLAP_W * BigInt(overlap) -
              UNION_W * BigInt(union) -
              penalty;
            matrix[row]![column] = -weight;
          });
        });

        const assignment = hungarian(matrix);
        component.gts.forEach((localGt, row) => {
          const column = assignment[row] ?? -1;
          if (column < 0 || column >= findingCount) return;
          const gtIndex = gtIndices[localGt]!;
          const findingIndex = findingIndices[component.findings[column]!]!;
          const gt = gtSorted[gtIndex]!;
          const finding = findingRecords[findingIndex]!.finding;
          const overlap = intersectionSize([gt], [finding]);
          if (overlap <= 0) return;
          const union = spanSize(gt) + spanSize(finding) - overlap;
          assigned.set(gtIndex, { findingIndex, overlap, union });
        });
      }
    }
  }

  return gtSorted.map((gt, index) => {
    const edge = assigned.get(index);
    if (!edge) {
      return { run_id: runId, gt_id: gt.id, merged_id: null, overlap: 0, union: 0 };
    }
    return {
      run_id: runId,
      gt_id: gt.id,
      merged_id: findingRecords[edge.findingIndex]!.mergedId,
      overlap: edge.overlap,
      union: edge.union,
    };
  });
}
