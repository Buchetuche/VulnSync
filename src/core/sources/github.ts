// Cliente de la GitHub Advisory Database (REST: GET /advisories).
// Se consulta con el parámetro `affects=pkg@versión` (hasta 1000 por petición)
// y se verifica cada rango localmente para evitar falsos positivos.

import { Dependency, Ecosystem, Finding, Severity } from '../types';
import { normalizeName } from '../text';
import { satisfiesGhsaRange } from '../version';

export type FetchLike = (url: string, init?: { headers?: Record<string, string>; signal?: AbortSignal }) => Promise<{
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

const API = 'https://api.github.com/advisories';
const MAX_URL = 7000;

export interface GithubClientOptions {
  fetch: FetchLike;
  token?: string;
  signal?: AbortSignal;
  onProgress?: (done: number, total: number) => void;
}

/** Consulta GHSA para todas las dependencias con versión conocida. */
export async function queryGithubAdvisories(deps: Dependency[], opts: GithubClientOptions): Promise<GhsaAdvisory[]> {
  const byEco = new Map<Ecosystem, Set<string>>();
  for (const d of deps) {
    if (!d.version) continue;
    if (!byEco.has(d.ecosystem)) byEco.set(d.ecosystem, new Set());
    byEco.get(d.ecosystem)!.add(`${d.name}@${d.version}`);
  }

  // Lotes que respetan el límite de 1000 paquetes y la longitud de URL.
  const batches: { eco: Ecosystem; items: string[] }[] = [];
  for (const [eco, set] of byEco) {
    let cur: string[] = [];
    let len = 0;
    for (const item of [...set].sort()) {
      const enc = encodeURIComponent(item).length + 3;
      if (cur.length && (cur.length >= 1000 || len + enc > MAX_URL)) { batches.push({ eco, items: cur }); cur = []; len = 0; }
      cur.push(item); len += enc;
    }
    if (cur.length) batches.push({ eco, items: cur });
  }

  const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'User-Agent': 'vulnsync-vscode' };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;

  const all = new Map<string, GhsaAdvisory>();
  let done = 0;
  for (const b of batches) {
    let url: string | undefined =
      `${API}?ecosystem=${b.eco}&per_page=100&affects=${b.items.map(encodeURIComponent).join(',')}`;
    while (url) {
      const res = await opts.fetch(url, { headers, signal: opts.signal });
      if (res.status === 429 || (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0')) {
        const reset = res.headers.get('x-ratelimit-reset');
        throw new RateLimitError(reset ? new Date(parseInt(reset, 10) * 1000) : undefined, !!opts.token);
      }
      if (!res.ok) throw new Error(`GitHub Advisory API respondió ${res.status}: ${(await res.text()).slice(0, 200)}`);
      const page = (await res.json()) as GhsaAdvisory[];
      for (const a of page) if (!a.withdrawn_at) all.set(a.ghsa_id, a);
      url = nextLink(res.headers.get('link'));
    }
    opts.onProgress?.(++done, batches.length);
  }
  return [...all.values()];
}

function nextLink(link: string | null): string | undefined {
  if (!link) return undefined;
  const m = /<([^>]+)>;\s*rel="next"/.exec(link);
  return m?.[1];
}

/** Cruza los boletines con las dependencias y produce hallazgos verificados. */
export function matchGithubAdvisories(deps: Dependency[], advisories: GhsaAdvisory[]): Finding[] {
  const index = new Map<string, Dependency[]>();
  for (const d of deps) {
    if (!d.version) continue;
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
        if (!satisfiesGhsaRange(d.version!, v.vulnerable_version_range)) continue;
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
          installedVersion: d.version,
          vulnerableRange: v.vulnerable_version_range,
          fixedVersion: v.first_patched_version ?? undefined,
          uncertain: !!d.approximate,
          location: d.location,
          direct: d.direct,
        });
      }
    }
  }
  return out;
}
