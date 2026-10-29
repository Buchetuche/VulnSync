// Cliente de la GitHub Advisory Database (REST: GET /advisories).
// - Dependencias con versión exacta: `affects=pkg@versión` y verificación local del rango.
// - Dependencias solo con rango declarado: `affects=pkg` (todos los avisos del paquete) y
//   comparación local de la intersección entre el rango declarado y el vulnerable.
// Cada lote se registra con su resultado para no presentar como verificado lo que no se consultó.

import { Dependency, Ecosystem, Finding, Severity } from '../types';
import { normalizeName } from '../text';
import { declaredIntersectsVulnerable, declaredToIntervals, satisfiesGhsaRange } from '../version';

export type FetchLike = (url: string, init?: {
  headers?: Record<string, string>; signal?: AbortSignal; redirect?: 'error' | 'follow' | 'manual';
}) => Promise<{
  ok: boolean; status: number; headers: { get(name: string): string | null }; json(): Promise<any>; text(): Promise<string>;
}>;

export interface GhsaVulnerability {
  package: { ecosystem: string; name: string };
  vulnerable_version_range: string | null;
  first_patched_version: string | null;
}
export interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  severity: Severity;
  cvss?: { score: number | null } | null;
  cvss_severities?: { cvss_v3?: { score: number | null }; cvss_v4?: { score: number | null } } | null;
  withdrawn_at: string | null;
  vulnerabilities: GhsaVulnerability[];
}

export class RateLimitError extends Error {
  constructor(public resetAt: Date | undefined, public authenticated: boolean) {
    super('Límite de la API de GitHub alcanzado');
  }
}

const ORIGIN = 'https://api.github.com';
const PATH = '/advisories';
const API = ORIGIN + PATH;
const API_VERSION = '2022-11-28';
const MAX_URL = 7000;
const MAX_PAGES = 200;

/** Cómo se consulta y se compara una dependencia. */
export type DepMode = 'exact' | 'range' | 'unverified';

export function classifyDependency(d: Dependency): DepMode {
  if (d.version && !d.approximate) return 'exact';
  if (d.declared && declaredToIntervals(d.declared, d.ecosystem)) return 'range';
  return 'unverified';
}

/** Elemento `affects` de una dependencia (o undefined si no es consultable). */
export function queryItem(d: Dependency): string | undefined {
  const mode = classifyDependency(d);
  if (mode === 'exact') return `${d.name}@${d.version}`;
  if (mode === 'range') return d.name;
  return undefined;
}

export const queryKey = (eco: Ecosystem, item: string) => `${eco}|${item}`;

export interface GithubClientOptions {
  fetch: FetchLike;
  token?: string;
  signal?: AbortSignal;
  onProgress?: (done: number, total: number) => void;
}

export interface BatchResult {
  ecosystem: Ecosystem;
  items: string[];
  ok: boolean;
  error?: string;
}

export interface GithubQueryResult {
  advisories: GhsaAdvisory[];
  batches: BatchResult[];
  /** Claves `eco|item` cuyos lotes terminaron correctamente. */
  checked: Set<string>;
  errors: string[];
}

/** Solo se admiten URLs https://api.github.com/advisories sin credenciales ni puerto. */
export function isAllowedGithubUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && u.hostname === 'api.github.com' && !u.port
      && !u.username && !u.password && u.pathname === PATH;
  } catch { return false; }
}

export async function queryGithubAdvisories(deps: Dependency[], opts: GithubClientOptions): Promise<GithubQueryResult> {
  const byEco = new Map<Ecosystem, Set<string>>();
  for (const d of deps) {
    const item = queryItem(d);
    if (!item) continue;
    if (!byEco.has(d.ecosystem)) byEco.set(d.ecosystem, new Set());
    byEco.get(d.ecosystem)!.add(item);
  }

  // Lotes que respetan el límite de 1000 paquetes y la longitud de URL.
  const plan: { eco: Ecosystem; items: string[] }[] = [];
  for (const [eco, set] of byEco) {
    let cur: string[] = [];
    let len = 0;
    for (const item of [...set].sort()) {
      const enc = encodeURIComponent(item).length + 3;
      if (cur.length && (cur.length >= 1000 || len + enc > MAX_URL)) { plan.push({ eco, items: cur }); cur = []; len = 0; }
      cur.push(item); len += enc;
    }
    if (cur.length) plan.push({ eco, items: cur });
  }

  const baseHeaders: Record<string, string> = {
    Accept: 'application/vnd.github+json', 'User-Agent': 'vulnsync-vscode', 'X-GitHub-Api-Version': API_VERSION,
  };

  const all = new Map<string, GhsaAdvisory>();
  const result: GithubQueryResult = { advisories: [], batches: [], checked: new Set(), errors: [] };
  let done = 0;
  let stopError: string | undefined;

  for (const b of plan) {
    if (stopError) {
      result.batches.push({ ecosystem: b.eco, items: b.items, ok: false, error: stopError });
      continue;
    }
    const pageAdvisories: GhsaAdvisory[] = [];
    try {
      const base = `${API}?ecosystem=${b.eco}&per_page=100&affects=${b.items.map(encodeURIComponent).join(',')}`;
      let url: string | undefined = base;
      let pages = 0;
      while (url) {
        if (++pages > MAX_PAGES) throw new Error('Paginación de GitHub excedió el máximo de páginas');
        if (!isAllowedGithubUrl(url)) throw new Error('URL de GitHub no permitida; no se envían credenciales');
        const headers = { ...baseHeaders };
        if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
        const res = await opts.fetch(url, { headers, signal: opts.signal, redirect: 'error' });
        if (res.status === 429 || (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0')) {
          const reset = res.headers.get('x-ratelimit-reset');
          throw new RateLimitError(reset ? new Date(parseInt(reset, 10) * 1000) : undefined, !!opts.token);
        }
        if (!res.ok) throw new Error(`GitHub Advisory API respondió ${res.status}: ${(await res.text()).slice(0, 200)}`);
        const page = await res.json();
        if (!Array.isArray(page)) throw new Error('Respuesta inválida de GitHub Advisory (se esperaba una lista)');
        for (const a of page) if (a && typeof a.ghsa_id === 'string') pageAdvisories.push(a as GhsaAdvisory);
        const cursor = nextCursor(res.headers.get('link'));
        if (cursor === 'invalid') throw new Error('Paginación de GitHub rechazada: el enlace "next" apunta a otro origen');
        url = cursor ? `${base}&${cursor.key}=${encodeURIComponent(cursor.value)}` : undefined;
      }
      for (const a of pageAdvisories) if (!a.withdrawn_at) all.set(a.ghsa_id, a);
      result.batches.push({ ecosystem: b.eco, items: b.items, ok: true });
      for (const it of b.items) result.checked.add(queryKey(b.eco, it));
    } catch (e: any) {
      if (e?.name === 'AbortError') throw e;
      const msg = e?.message ?? String(e);
      result.batches.push({ ecosystem: b.eco, items: b.items, ok: false, error: msg });
      if (!result.errors.includes(msg)) result.errors.push(msg);
      if (e instanceof RateLimitError) stopError = msg;   // el resto de lotes tampoco podrá consultarse
    }
    opts.onProgress?.(++done, plan.length);
  }
  result.advisories = [...all.values()];
  return result;
}

/** Extrae solo el cursor (`after`/`before`) del enlace rel="next"; el resto de la URL se reconstruye. */
function nextCursor(link: string | null): { key: 'after' | 'before'; value: string } | 'invalid' | undefined {
  if (!link) return undefined;
  const m = /<([^>]+)>;\s*rel="next"/.exec(link);
  if (!m) return undefined;
  if (!isAllowedGithubUrl(m[1])) return 'invalid';
  const u = new URL(m[1]);
  for (const key of ['after', 'before'] as const) {
    const v = u.searchParams.get(key);
    if (v) return { key, value: v };
  }
  return 'invalid';
}

/** Cruza los boletines con las dependencias y produce hallazgos. */
export function matchGithubAdvisories(deps: Dependency[], advisories: GhsaAdvisory[]): Finding[] {
  const index = new Map<string, Dependency[]>();
  for (const d of deps) {
    if (classifyDependency(d) === 'unverified') continue;
    const k = `${d.ecosystem}|${normalizeName(d.ecosystem, d.name)}`;
    if (!index.has(k)) index.set(k, []);
    index.get(k)!.push(d);
  }
  const out: Finding[] = [];
  for (const a of advisories) {
    for (const v of a.vulnerabilities ?? []) {
      const eco = v.package.ecosystem as Ecosystem;
      const candidates = index.get(`${eco}|${normalizeName(eco, v.package.name)}`);
      if (!candidates || !v.vulnerable_version_range) continue;
      for (const d of candidates) {
        const exact = classifyDependency(d) === 'exact';
        const hit = exact
          ? satisfiesGhsaRange(d.version!, v.vulnerable_version_range)
          : declaredIntersectsVulnerable(d.declared!, d.ecosystem, v.vulnerable_version_range) !== false;
        if (!hit) continue;
        out.push({
          id: a.ghsa_id,
          aliases: a.cve_id ? [a.cve_id] : [],
          source: 'github',
          severity: a.severity ?? 'unknown',
          cvss: a.cvss_severities?.cvss_v4?.score ?? a.cvss_severities?.cvss_v3?.score ?? a.cvss?.score ?? undefined,
          title: a.summary,
          url: a.html_url,
          packageName: d.name,
          ecosystem: d.ecosystem,
          installedVersion: exact ? d.version : undefined,
          declaredRange: exact ? undefined : d.declared,
          vulnerableRange: v.vulnerable_version_range,
          fixedVersion: v.first_patched_version ?? undefined,
          uncertain: !exact,
          location: d.location,
          direct: d.direct,
        });
      }
    }
  }
  return out;
}
