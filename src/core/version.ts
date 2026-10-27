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
    if (br) return br[1];
    // En NuGet "1.2.3" significa >=1.2.3, pero la restauración elige exactamente
    // la mínima disponible, así que en la práctica es la versión usada.
    return /^\d+(\.\d+){0,3}(-[0-9A-Za-z.\-]+)?$/.test(d) ? d : undefined;
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
