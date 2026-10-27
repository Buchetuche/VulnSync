// Cliente de la API CVRF v3.0 del Microsoft Security Response Center.
//   GET https://api.msrc.microsoft.com/cvrf/v3.0/updates        → lista de boletines mensuales
//   GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{ID}      → documento CVRF (JSON con Accept)
// Los documentos son grandes (varios MB), así que se reducen a las entradas
// de .NET / ASP.NET Core y se guardan en caché por ID + CurrentReleaseDate.

import { Finding, RuntimeTarget, Severity } from '../types';
import { compareVersions, majorMinor } from '../version';
import { FetchLike } from './github';

const BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0';

export interface MsrcEntry {
  cve: string;
  title: string;
  severity: Severity;
  cvss?: number;
  product: '.NET' | 'ASP.NET Core';
  band: string;           // "8.0"
  productName: string;    // ".NET 8.0 installed on Windows"
  fixedBuild?: string;    // "8.0.11"
  kb?: string;
  docId: string;          // "2026-Oct"
}

export interface MsrcCache {
  syncedAt?: string;
  docs: Record<string, { currentReleaseDate: string; entries: MsrcEntry[] }>;
}

export interface MsrcUpdate {
  ID: string;
  DocumentTitle: string;
  InitialReleaseDate: string;
  CurrentReleaseDate: string;
  CvrfUrl: string;
}

export async function listMsrcUpdates(fetch: FetchLike, signal?: AbortSignal): Promise<MsrcUpdate[]> {
  const res = await fetch(`${BASE}/updates`, { headers: { Accept: 'application/json' }, signal });
  if (!res.ok) throw new Error(`MSRC /updates respondió ${res.status}`);
  const body = await res.json();
  return (body?.value ?? []) as MsrcUpdate[];
}

/**
 * Sincroniza incrementalmente los últimos `months` boletines.
 * Solo descarga los documentos nuevos o revisados desde la última vez.
 */
export async function syncMsrc(
  fetch: FetchLike, cache: MsrcCache, months: number,
  opts: { signal?: AbortSignal; onProgress?: (msg: string) => void } = {},
): Promise<{ cache: MsrcCache; downloaded: number }> {
  const updates = (await listMsrcUpdates(fetch, opts.signal))
    .filter(u => /^\d{4}-[A-Za-z]{3}$/.test(u.ID))
    .sort((a, b) => b.InitialReleaseDate.localeCompare(a.InitialReleaseDate))
    .slice(0, months);

  const next: MsrcCache = { syncedAt: new Date().toISOString(), docs: {} };
  let downloaded = 0;
  for (const u of updates) {
    const prev = cache.docs[u.ID];
    if (prev && prev.currentReleaseDate === u.CurrentReleaseDate) { next.docs[u.ID] = prev; continue; }
    opts.onProgress?.(`Descargando boletín MSRC ${u.ID}…`);
    const res = await fetch(u.CvrfUrl || `${BASE}/cvrf/${u.ID}`, { headers: { Accept: 'application/json' }, signal: opts.signal });
    if (!res.ok) {
      if (prev) next.docs[u.ID] = prev; // conserva lo anterior si falla
      continue;
    }
    next.docs[u.ID] = { currentReleaseDate: u.CurrentReleaseDate, entries: reduceCvrf(await res.json(), u.ID) };
    downloaded++;
  }
  return { cache: next, downloaded };
}

const PRODUCT_RE = /^(?:Microsoft\s+)?(ASP\.NET Core|\.NET Core|\.NET)\s+(\d+)\.(\d+)\b/i;

/** Reduce un documento CVRF completo a las entradas de .NET / ASP.NET Core. */
export function reduceCvrf(doc: any, docId: string): MsrcEntry[] {
  const products = new Map<string, { product: MsrcEntry['product']; band: string; name: string }>();
  for (const p of flattenProducts(doc?.ProductTree)) {
    const name: string = p.Value ?? '';
    if (/Framework|Visual Studio|MAUI|nanoFramework/i.test(name)) continue;
    const m = PRODUCT_RE.exec(name);
    if (!m) continue;
    products.set(String(p.ProductID), {
      product: /^ASP/i.test(m[1]) ? 'ASP.NET Core' : '.NET',
      band: `${m[2]}.${m[3]}`,
      name,
    });
  }
  if (!products.size) return [];

  const out: MsrcEntry[] = [];
  for (const v of asArray(doc?.Vulnerability)) {
    const cve: string = v?.CVE;
    if (!cve) continue;
    const affected = new Set<string>();
    for (const s of asArray(v.ProductStatuses)) {
      if (s?.Type === 3 || s?.Type === undefined) for (const id of asArray(s.ProductID)) affected.add(String(id));
    }
    const seenBand = new Set<string>();
    for (const pid of affected) {
      const prod = products.get(pid);
      if (!prod) continue;
      const key = `${prod.product}|${prod.band}`;
      if (seenBand.has(key)) continue; // una entrada por producto+banda (Windows/Linux/macOS)
      seenBand.add(key);

      const threat = asArray(v.Threats).find((t: any) => t?.Type === 3 && includesId(t.ProductID, pid))
        ?? asArray(v.Threats).find((t: any) => t?.Type === 3);
      const score = asArray(v.CVSSScoreSets).find((c: any) => includesId(c.ProductID, pid))?.BaseScore
        ?? asArray(v.CVSSScoreSets)[0]?.BaseScore;
      const rem = asArray(v.Remediations).filter((r: any) => includesId(r.ProductID, pid));
      const fixed = rem
        .map((r: any) => r.FixedBuild || r.Description?.Value)
        .filter((s: any) => typeof s === 'string' && /^\d+\.\d+\.\d+/.test(s.trim()))
        .map((s: string) => s.trim())
        .filter((s: string) => majorMinor(s) === prod.band)
        .sort(compareVersions)
        .pop();
      const kb = rem.map((r: any) => r.Description?.Value).find((s: any) => typeof s === 'string' && /^\d{6,8}$/.test(s));

      out.push({
        cve,
        title: v.Title?.Value ?? cve,
        severity: mapSeverity(threat?.Description?.Value),
        cvss: typeof score === 'number' ? score : undefined,
        product: prod.product,
        band: prod.band,
        productName: prod.name,
        fixedBuild: fixed,
        kb: kb ? `KB${kb}` : undefined,
        docId,
      });
    }
  }
  return out;
}

function flattenProducts(tree: any): any[] {
  const out: any[] = [...asArray(tree?.FullProductName)];
  const walk = (branches: any) => {
    for (const b of asArray(branches)) {
      out.push(...asArray(b?.FullProductName));
      walk(b?.Items ?? b?.Branch);
    }
  };
  walk(tree?.Branch);
  return out;
}

function mapSeverity(s: string | undefined): Severity {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'important': return 'high';
    case 'moderate': return 'medium';
    case 'low': return 'low';
    default: return 'unknown';
  }
}

const asArray = (x: any): any[] => (Array.isArray(x) ? x : x == null ? [] : [x]);
const includesId = (ids: any, id: string) => asArray(ids).map(String).includes(id);

/** Runtimes instalados según `dotnet --list-runtimes`. */
export function parseDotnetListRuntimes(output: string): { product: MsrcEntry['product']; version: string }[] {
  const out: { product: MsrcEntry['product']; version: string }[] = [];
  for (const line of output.split(/\r?\n/)) {
    const m = /^(Microsoft\.NETCore\.App|Microsoft\.AspNetCore\.App)\s+(\S+)/.exec(line.trim());
    if (m) out.push({ product: m[1] === 'Microsoft.AspNetCore.App' ? 'ASP.NET Core' : '.NET', version: m[2] });
  }
  return out;
}

/**
 * Cruza los boletines MSRC con los runtimes detectados en el proyecto.
 * - Si hay versión fijada (RuntimeFrameworkVersion) o instalada, se compara con FixedBuild.
 * - Si no se conoce la versión, el hallazgo se marca como "incierto".
 */
export function matchMsrc(
  targets: RuntimeTarget[], entries: MsrcEntry[],
  installed: { product: MsrcEntry['product']; version: string }[] | undefined,
): Finding[] {
  const out: Finding[] = [];
  for (const t of targets) {
    const candidates = entries.filter(e => e.product === t.product && e.band === t.band);
    if (!candidates.length) continue;
    const inBand = (installed ?? [])
      .filter(i => i.product === t.product && majorMinor(i.version) === t.band)
      .map(i => i.version)
      .sort(compareVersions);
    const effective = t.version ?? inBand.pop();
    for (const e of candidates) {
      if (effective && e.fixedBuild && compareVersions(effective, e.fixedBuild) >= 0) continue;
      const uncertain = !effective || !e.fixedBuild;
      out.push({
        id: e.cve,
        aliases: e.kb ? [e.kb] : [],
        source: 'msrc',
        severity: e.severity,
        cvss: e.cvss,
        title: e.title,
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${e.cve}`,
        packageName: `${t.product} ${t.band}`,
        ecosystem: 'runtime',
        installedVersion: effective,
        vulnerableRange: e.fixedBuild ? `< ${e.fixedBuild}` : undefined,
        fixedVersion: e.fixedBuild,
        uncertain,
        location: t.location,
        direct: true,
      });
    }
  }
  return out;
}
