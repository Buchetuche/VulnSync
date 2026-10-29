// Comparación de versiones tolerante para npm (semver), NuGet (hasta 4 partes)
// y PyPI (PEP 440 simplificado), más evaluación de los rangos de GHSA
// ("< 1.2.3", ">= 1.0.0, < 1.4.2", "= 2.0.0").

import { Ecosystem } from './types';

interface Parsed {
  release: number[];
  /** Etapa: -3 dev, -2 alpha/a, -1 beta/b, 0 rc/pre/otros, 1 release, 2 post */
  stage: number;
  stageNum: number;
  preTokens: (string | number)[];
}

const STAGES: Record<string, number> = {
  dev: -4, alpha: -3, a: -3, beta: -2, b: -2, c: -1, rc: -1, pre: -1, preview: -1,
  post: 2, rev: 2, r: 2,
};

export function normalizeVersion(v: string): string {
  return v.trim().replace(/^[=v\s]+/i, '').replace(/^\d+!/, '');
}

export function parseVersion(input: string): Parsed | undefined {
  const v = normalizeVersion(input).split('+')[0].toLowerCase();
  const m = /^(\d+(?:\.\d+)*)(.*)$/.exec(v);
  if (!m) return undefined;
  const release = m[1].split('.').map(n => parseInt(n, 10));
  let rest = m[2];
  if (!rest) return { release, stage: 1, stageNum: 0, preTokens: [] };

  // PEP 440: 1.0.post1, 1.0rc1, 1.0.dev3, 1.0a1
  const pep = /^[-._]?(dev|alpha|a|beta|b|c|rc|pre|preview|post|rev|r)[-._]?(\d*)/.exec(rest);
  if (pep) {
    return {
      release,
      stage: STAGES[pep[1]] ?? 0,
      stageNum: pep[2] ? parseInt(pep[2], 10) : 0,
      preTokens: rest.slice(pep[0].length).split(/[.\-]/).filter(Boolean).map(tok),
    };
  }
  // semver / NuGet: 1.0.0-beta.2
  if (rest.startsWith('-')) rest = rest.slice(1);
  const tokens = rest.split(/[.\-]/).filter(Boolean).map(tok);
  return { release, stage: 0, stageNum: 0, preTokens: tokens };
}

function tok(s: string): string | number {
  return /^\d+$/.test(s) ? parseInt(s, 10) : s;
}

/** Devuelve <0, 0, >0. Versiones no interpretables se comparan como texto. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  if (!pa || !pb) return a.localeCompare(b);
  const len = Math.max(pa.release.length, pb.release.length);
  for (let i = 0; i < len; i++) {
    const d = (pa.release[i] ?? 0) - (pb.release[i] ?? 0);
    if (d !== 0) return d;
  }
  if (pa.stage !== pb.stage) return pa.stage - pb.stage;
  if (pa.stageNum !== pb.stageNum) return pa.stageNum - pb.stageNum;
  const tl = Math.max(pa.preTokens.length, pb.preTokens.length);
  for (let i = 0; i < tl; i++) {
    const x = pa.preTokens[i];
    const y = pb.preTokens[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === 'number' && typeof y === 'number') { if (x !== y) return x - y; continue; }
    if (typeof x === 'number') return -1;
    if (typeof y === 'number') return 1;
    const c = x.localeCompare(y);
    if (c !== 0) return c;
  }
  return 0;
}

/**
 * Evalúa un rango GHSA. Formato: restricciones separadas por coma,
 * cada una "<op> <versión>" con op ∈ {=, <, <=, >, >=}.
 */
export function satisfiesGhsaRange(version: string, range: string): boolean {
  const parts = range.split(',').map(s => s.trim()).filter(Boolean);
  if (parts.length === 0) return false;
  for (const p of parts) {
    const m = /^(<=|>=|<|>|=)?\s*(.+)$/.exec(p);
    if (!m) return false;
    const op = m[1] ?? '=';
    const c = compareVersions(version, m[2]);
    const ok =
      op === '=' ? c === 0 :
      op === '<' ? c < 0 :
      op === '<=' ? c <= 0 :
      op === '>' ? c > 0 :
      c >= 0;
    if (!ok) return false;
  }
  return true;
}

/**
 * Para un rango declarado sin lockfile, devuelve la versión mínima que
 * admitiría el rango (aproximación): "^4.17.1" → "4.17.1", ">=2.0,<3" → "2.0",
 * "[1.0,2.0)" (NuGet) → "1.0". Devuelve undefined si es un comodín o un tag.
 */
export function lowerBoundOf(declared: string, eco: Ecosystem): string | undefined {
  let d = declared.trim();
  if (!d || d === '*' || d === 'latest' || /^[xX]$/.test(d)) return undefined;
  if (eco === 'nuget') {
    const m = /^[\[(]\s*([^,\])]*)/.exec(d);
    if (m) d = m[1];
    if (d.includes('*')) d = d.replace(/\.?\*.*/, '') || '';
  }
  if (eco === 'npm') {
    // primer comparador de la primera alternativa (a || b)
    d = d.split('||')[0].trim();
    if (/^(file:|link:|git|https?:|workspace:|npm:)/.test(d)) return undefined;
  }
  const m = /(\d+(?:\.(?:\d+|[xX*]))*(?:[-.]?[0-9A-Za-z.\-]+)?)/.exec(d);
  if (!m) return undefined;
  return m[1].replace(/\.[xX*].*$/, '').replace(/\.$/, '');
}

/** Exacto si el rango declarado ya fija una sola versión. */
export function exactPin(declared: string, eco: Ecosystem): string | undefined {
  const d = declared.trim();
  if (eco === 'pip') {
    const m = /^===?\s*([0-9][^\s,;]*)$/.exec(d);
    return m && !m[1].includes('*') ? m[1] : undefined;
  }
  if (eco === 'nuget') {
    const br = /^\[\s*([^,\]]+)\s*\]$/.exec(d);
    // En NuGet "1.2.3" significa >=1.2.3: sin lockfile NO es la versión instalada.
    return br ? br[1] : undefined;
  }
  // npm
  const m = /^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)$/.exec(d);
  return m ? m[1] : undefined;
}

export function majorMinor(v: string): string | undefined {
  const p = parseVersion(v);
  if (!p) return undefined;
  return `${p.release[0]}.${p.release[1] ?? 0}`;
}

// ---------- Intervalos de versiones (VS-002) ----------

/** Intervalo de versiones; un límite ausente significa "sin límite". */
export interface Interval {
  lo?: string; loInc: boolean;
  hi?: string; hiInc: boolean;
}

const ALL: Interval = { loInc: true, hiInc: true };

function intervalEmpty(i: Interval): boolean {
  if (i.lo === undefined || i.hi === undefined) return false;
  const c = compareVersions(i.lo, i.hi);
  return c > 0 || (c === 0 && !(i.loInc && i.hiInc));
}

function intersectIntervals(a: Interval, b: Interval): Interval {
  let lo = a.lo, loInc = a.loInc;
  if (b.lo !== undefined) {
    const c = lo === undefined ? 1 : compareVersions(b.lo, lo);
    if (c > 0) { lo = b.lo; loInc = b.loInc; } else if (c === 0) loInc = loInc && b.loInc;
  }
  let hi = a.hi, hiInc = a.hiInc;
  if (b.hi !== undefined) {
    const c = hi === undefined ? -1 : compareVersions(b.hi, hi);
    if (c < 0) { hi = b.hi; hiInc = b.hiInc; } else if (c === 0) hiInc = hiInc && b.hiInc;
  }
  return { lo, loInc, hi, hiInc };
}

/** Aplica un comparador (op, versión) a un intervalo acumulado. */
function applyComparator(cur: Interval, op: string, v: string): Interval {
  switch (op) {
    case '>': return intersectIntervals(cur, { lo: v, loInc: false, hiInc: true });
    case '>=': return intersectIntervals(cur, { lo: v, loInc: true, hiInc: true });
    case '<': return intersectIntervals(cur, { hi: v, hiInc: false, loInc: true });
    case '<=': return intersectIntervals(cur, { hi: v, hiInc: true, loInc: true });
    default: return intersectIntervals(cur, { lo: v, loInc: true, hi: v, hiInc: true });
  }
}

const bump = (parts: number[], idx: number): string => {
  const out = parts.slice(0, idx + 1);
  out[idx] += 1;
  return out.join('.');
};

/** "1.2.x" → [1.2.0, 1.3.0); "1" → [1.0.0, 2.0.0). undefined si no es parcial/comodín. */
function partialRange(s: string): Interval | undefined {
  const m = /^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$/.exec(s.trim());
  if (!m) return undefined;
  const nums: number[] = [];
  for (const g of [m[1], m[2], m[3]]) {
    if (g === undefined || /^[xX*]$/.test(g)) break;
    nums.push(parseInt(g, 10));
  }
  if (nums.length >= 3 && m[3] !== undefined && !/^[xX*]$/.test(m[3])) return undefined;
  return { lo: nums.join('.'), loInc: true, hi: bump(nums, nums.length - 1), hiInc: false };
}

/** Rango de GHSA ("">= 1.0, < 2.0"") → un intervalo, o undefined si no se entiende. */
export function ghsaRangeToInterval(range: string): Interval | undefined {
  const parts = range.split(',').map(s => s.trim()).filter(Boolean);
  if (!parts.length) return undefined;
  let cur: Interval = { ...ALL };
  for (const p of parts) {
    const m = /^(<=|>=|<|>|=)?\s*(\S+)$/.exec(p);
    if (!m) return undefined;
    cur = applyComparator(cur, m[1] ?? '=', m[2]);
  }
  return cur;
}

function caret(v: string): Interval | undefined {
  const p = parseVersion(v);
  if (!p) return undefined;
  const r = p.release.slice(0, 3);
  while (r.length < 3) r.push(0);
  const i = r.findIndex(n => n !== 0);
  const idx = i < 0 ? 2 : Math.min(i, 2);
  return { lo: normalizeVersion(v), loInc: true, hi: bump(r, idx), hiInc: false };
}

function tilde(v: string, parts: number): Interval | undefined {
  const p = parseVersion(v);
  if (!p) return undefined;
  const r = p.release.slice(0, 3);
  const idx = parts >= 2 ? 1 : 0;
  return { lo: normalizeVersion(v), loInc: true, hi: bump(r, idx), hiInc: false };
}

function npmComparatorSet(set: string): Interval | undefined {
  const s = set.trim();
  if (!s || s === '*' || /^[xX]$/.test(s) || s === 'latest') return { ...ALL };
  const hy = /^(\S+)\s+-\s+(\S+)$/.exec(s);
  if (hy) {
    const lo = partialRange(hy[1]);
    const hi = partialRange(hy[2]);
    if (!lo || !hi) return undefined;
    return { lo: lo.lo, loInc: true, hi: hi.hi, hiInc: false };
  }
  let cur: Interval = { ...ALL };
  const tokens = s.replace(/(<=|>=|<|>|=|\^|~>?)\s+/g, '$1').split(/\s+/);
  for (const t of tokens) {
    let m = /^\^(.+)$/.exec(t);
    if (m) { const i = caret(m[1]); if (!i) return undefined; cur = intersectIntervals(cur, i); continue; }
    m = /^~>?(.+)$/.exec(t);
    if (m) {
      const n = (m[1].match(/\.|$/g) ?? []).length;
      const i = tilde(m[1].replace(/\.[xX*].*$/, ''), n); if (!i) return undefined;
      cur = intersectIntervals(cur, i); continue;
    }
    m = /^(<=|>=|<|>|=)?(.+)$/.exec(t);
    if (!m) return undefined;
    const op = m[1] ?? '=';
    const pr = partialRange(m[2]);
    if (pr && (/[xX*]/.test(m[2]) || m[2].split('.').length < 3)) {
      if (op === '=') cur = intersectIntervals(cur, pr);
      else if (op === '>=') cur = applyComparator(cur, '>=', pr.lo!);
      else if (op === '>') cur = applyComparator(cur, '>=', pr.hi!);
      else if (op === '<') cur = applyComparator(cur, '<', pr.lo!);
      else cur = applyComparator(cur, '<', pr.hi!);
      continue;
    }
    if (!parseVersion(m[2])) return undefined;
    cur = applyComparator(cur, op, normalizeVersion(m[2]));
  }
  return cur;
}

function pipSpecifierSet(spec: string): Interval | undefined {
  const s = spec.trim();
  if (!s || s === '*') return { ...ALL };
  let cur: Interval = { ...ALL };
  for (const raw of s.split(',').map(x => x.trim()).filter(Boolean)) {
    let m = /^\^\s*(\S+)$/.exec(raw);          // Poetry
    if (m) { const i = caret(m[1]); if (!i) return undefined; cur = intersectIntervals(cur, i); continue; }
    m = /^~(?!=)\s*(\S+)$/.exec(raw);          // Poetry
    if (m) { const i = tilde(m[1], m[1].split('.').length); if (!i) return undefined; cur = intersectIntervals(cur, i); continue; }
    m = /^~=\s*(\S+)$/.exec(raw);              // PEP 440 compatible release
    if (m) {
      const p = parseVersion(m[1]);
      if (!p || p.release.length < 2) return undefined;
      const r = p.release.slice(0, -1);
      cur = intersectIntervals(cur, { lo: normalizeVersion(m[1]), loInc: true, hi: bump(r, r.length - 1), hiInc: false });
      continue;
    }
    m = /^===?\s*(\S+?)(\.\*)?$/.exec(raw);
    if (m) {
      if (m[2]) {
        const pr = partialRange(m[1] + '.*'); if (!pr) return undefined;
        cur = intersectIntervals(cur, pr);
      } else cur = applyComparator(cur, '=', normalizeVersion(m[1]));
      continue;
    }
    if (/^!=/.test(raw)) continue;             // una exclusión solo estrecha: superconjunto seguro
    m = /^(<=|>=|<|>)\s*(\S+)$/.exec(raw);
    if (!m || !parseVersion(m[2])) return undefined;
    cur = applyComparator(cur, m[1], normalizeVersion(m[2]));
  }
  return cur;
}

function nugetRange(spec: string): Interval | undefined {
  const s = spec.trim();
  if (!s || s === '*') return { ...ALL };
  const br = /^([\[(])\s*([^,\])]*?)\s*(?:(,)\s*([^,\])]*?)\s*)?([\])])$/.exec(s);
  if (br) {
    const lo = br[2] || undefined;
    const hi = br[3] ? (br[4] || undefined) : lo;
    if ((lo && !parseVersion(lo)) || (hi && !parseVersion(hi))) return undefined;
    return { lo, loInc: br[1] === '[', hi, hiInc: br[5] === ']' };
  }
  if (s.includes('*')) {
    const pr = partialRange(s.replace(/-\*$/, '').replace(/\.\*$/, '.x'));
    return pr ? { lo: pr.lo, loInc: true, hiInc: true } : undefined;
  }
  if (!parseVersion(s)) return undefined;
  return { lo: normalizeVersion(s), loInc: true, hiInc: true };   // "1.2.3" ≡ >= 1.2.3
}

/**
 * Convierte un rango declarado (SemVer, PEP 440/Poetry o NuGet) en una lista
 * de intervalos (unión). undefined = no se pudo interpretar.
 */
export function declaredToIntervals(declared: string, eco: Ecosystem): Interval[] | undefined {
  const d = declared.trim();
  if (!d) return undefined;
  if (eco === 'npm') {
    if (/^(file:|link:|git|https?:|workspace:|npm:|github:)/.test(d) || /^[\w.-]+\/[\w.-]+$/.test(d)) return undefined;
    const sets = d.split('||').map(npmComparatorSet);
    return sets.every(Boolean) ? (sets as Interval[]).filter(i => !intervalEmpty(i)) : undefined;
  }
  const one = eco === 'pip' ? pipSpecifierSet(d) : nugetRange(d);
  return one ? (intervalEmpty(one) ? [] : [one]) : undefined;
}

export function intervalsOverlap(a: Interval, b: Interval): boolean {
  return !intervalEmpty(intersectIntervals(a, b));
}

/**
 * ¿Alguna versión permitida por el rango declarado cae en el rango vulnerable?
 * 'unknown' cuando alguno de los dos rangos no se puede interpretar.
 */
export function declaredIntersectsVulnerable(
  declared: string, eco: Ecosystem, vulnerableRange: string,
): boolean | 'unknown' {
  const dec = declaredToIntervals(declared, eco);
  const vul = ghsaRangeToInterval(vulnerableRange);
  if (!dec || !vul) return 'unknown';
  return dec.some(d => intervalsOverlap(d, vul));
}
