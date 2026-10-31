// Cliente de la API CVRF v3.0 del Microsoft Security Response Center.
//   GET https://api.msrc.microsoft.com/cvrf/v3.0/updates        → lista de boletines mensuales
//   GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{ID}      → documento CVRF (JSON con Accept)
// Los documentos son grandes (varios MB), así que se reducen a las entradas
// de .NET / ASP.NET Core y se guardan en caché por ID + CurrentReleaseDate.

import { Finding, RuntimeTarget, Severity, SourceStatus } from '../types';
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
  fixedBuild?: string;    // versión de runtime que corrige: "8.0.11"
  sdkFixedBuild?: string; // versión de SDK que corrige: "8.0.427" (parche >= 100)
  kb?: string;
  docId: string;          // "2026-Oct"
}

export interface MsrcDoc {
  currentReleaseDate: string;
  entries: MsrcEntry[];
  /** Cuándo se descargó este documento. */
  fetchedAt?: string;
}

/** Un documento que no pudo descargarse en la última sincronización. */
export interface MsrcFailure {
  id: string;
  error: string;
  attempts: number;
  lastAttemptAt: string;
  nextRetryAt: string;
}

/**
 * Versión del formato/reducción de la caché. Subirla cada vez que cambie `reduceCvrf` o `MsrcEntry`:
 * una caché de otra versión se descarta y se vuelve a descargar (si no, conservaría resultados erróneos).
 * 2: separa versiones de runtime y de SDK (`sdkFixedBuild`).
 */
export const MSRC_CACHE_SCHEMA = 2;

export interface MsrcCache {
  schema?: number;
  /** Última sincronización COMPLETA (sin documentos fallidos). */
  syncedAt?: string;
  /** Último intento, completo o no. */
  lastAttemptAt?: string;
  docs: Record<string, MsrcDoc>;
  /** Documentos pendientes de reintento; vacío/ausente = caché completa. */
  failed?: MsrcFailure[];
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
const RETRY_BASE_MS = 5 * 60_000;
const RETRY_MAX_MS = 6 * 3600_000;

/** Backoff exponencial: 5 min, 10 min, 20 min… hasta 6 h. */
export function retryDelayMs(attempts: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** Math.max(0, attempts - 1));
}

/** Valida la caché leída del disco: cualquier otra versión o forma inesperada se descarta. */
export function normalizeMsrcCache(raw: any): MsrcCache {
  if (raw && typeof raw === 'object' && raw.schema === MSRC_CACHE_SCHEMA && raw.docs && typeof raw.docs === 'object') {
    return raw as MsrcCache;
  }
  return { schema: MSRC_CACHE_SCHEMA, docs: {} };
}

/** ¿Toca sincronizar? Por antigüedad de la última sincronización completa o por reintentos vencidos. */
export function msrcNeedsSync(cache: MsrcCache, now: number, intervalMs: number): boolean {
  if (!cache.syncedAt || now - Date.parse(cache.syncedAt) > intervalMs) return true;
  return (cache.failed ?? []).some(f => Date.parse(f.nextRetryAt) <= now);
}

/**
 * Sincroniza incrementalmente los últimos `months` boletines.
 * Solo descarga los documentos nuevos o revisados desde la última vez.
 * Un documento que falla conserva su copia anterior (si existe) y queda en
 * `cache.failed`; `syncedAt` solo se actualiza si TODOS los documentos están al día.
 */
export async function syncMsrc(
  fetch: FetchLike, cache: MsrcCache, months: number,
  opts: { signal?: AbortSignal; onProgress?: (msg: string) => void; now?: () => number } = {},
): Promise<{ cache: MsrcCache; downloaded: number; failed: MsrcFailure[] }> {
  const nowMs = opts.now ?? Date.now;
  const updates = (await listMsrcUpdates(fetch, opts.signal))
    .filter(u => /^\d{4}-[A-Za-z]{3}$/.test(u.ID))
    .sort((a, b) => b.InitialReleaseDate.localeCompare(a.InitialReleaseDate))
    .slice(0, months);

  const attemptAt = new Date(nowMs()).toISOString();
  const next: MsrcCache = { schema: MSRC_CACHE_SCHEMA, syncedAt: undefined, lastAttemptAt: attemptAt, docs: {}, failed: [] };
  const prevFailed = new Map((cache.failed ?? []).map(f => [f.id, f]));
  let downloaded = 0;
  for (const u of updates) {
    const prev = cache.docs[u.ID];
    if (prev && prev.currentReleaseDate === u.CurrentReleaseDate) { next.docs[u.ID] = prev; continue; }
    opts.onProgress?.(`Descargando boletín MSRC ${u.ID}…`);
    try {
      const res = await fetch(u.CvrfUrl || `${BASE}/cvrf/${u.ID}`, { headers: { Accept: 'application/json' }, signal: opts.signal });
      if (!res.ok) throw new Error(`MSRC ${u.ID} respondió ${res.status}`);
      const body = await res.json();
      if (!body || typeof body !== 'object') throw new Error(`MSRC ${u.ID}: documento inválido`);
      next.docs[u.ID] = { currentReleaseDate: u.CurrentReleaseDate, entries: reduceCvrf(body, u.ID), fetchedAt: attemptAt };
      downloaded++;
    } catch (e: any) {
      if (e?.name === 'AbortError') throw e;
      if (prev) next.docs[u.ID] = prev; // conserva lo anterior (desactualizado)
      const attempts = (prevFailed.get(u.ID)?.attempts ?? 0) + 1;
      next.failed!.push({
        id: u.ID, error: e?.message ?? String(e), attempts, lastAttemptAt: attemptAt,
        nextRetryAt: new Date(nowMs() + retryDelayMs(attempts)).toISOString(),
      });
    }
  }
  if (!next.failed!.length) next.syncedAt = attemptAt;
  else next.syncedAt = cache.syncedAt;   // conserva la última sincronización completa conocida
  return { cache: next, downloaded, failed: next.failed! };
}

/** Estado de la fuente MSRC a partir de la caché y del error de sincronización (si lo hubo). */
export function describeMsrcStatus(
  cache: MsrcCache | undefined, syncError: string | undefined, now = Date.now(),
): SourceStatus {
  const docs = Object.keys(cache?.docs ?? {}).length;
  const age = (iso?: string) => {
    if (!iso) return 'nunca sincronizada por completo';
    const h = Math.max(0, Math.round((now - Date.parse(iso)) / 3600_000));
    return `sincronizada el ${iso.slice(0, 10)} (hace ${h < 48 ? `${h} h` : `${Math.round(h / 24)} d`})`;
  };
  if (!cache || !docs) {
    return { source: 'msrc', state: 'failed', detail: `Sin boletines MSRC disponibles${syncError ? `: ${syncError}` : ''}` };
  }
  if (syncError) {
    return { source: 'msrc', state: 'cached', dataAsOf: cache.syncedAt,
      detail: `No se pudo sincronizar (${syncError}); se usa la caché, ${age(cache.syncedAt)}` };
  }
  if (cache.failed?.length) {
    return { source: 'msrc', state: 'partial', dataAsOf: cache.syncedAt,
      detail: `Boletines sin actualizar: ${cache.failed.map(f => `${f.id} (${f.error})`).join('; ')}` };
  }
  if (!cache.syncedAt) {
    return { source: 'msrc', state: 'cached', detail: 'Caché sin sincronización completa verificada' };
  }
  return { source: 'msrc', state: 'complete', dataAsOf: cache.syncedAt, detail: `${docs} boletines, ${age(cache.syncedAt)}` };
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
      // MSRC mezcla versiones de runtime (8.0.32) y de SDK (8.0.427, parche >= 100).
      // Solo las de runtime se pueden comparar con `dotnet --list-runtimes`.
      const builds: string[] = rem
        .map((r: any) => r.FixedBuild || r.Description?.Value)
        .filter((s: any) => typeof s === 'string' && /^\d+\.\d+\.\d+/.test(s.trim()))
        .map((s: string) => s.trim())
        .filter((s: string) => majorMinor(s) === prod.band)
        .sort(compareVersions);
      const fixed = builds.filter(isRuntimeBuild).pop();
      const sdkFixed = builds.filter(b => !isRuntimeBuild(b)).pop();
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
        sdkFixedBuild: sdkFixed,
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

/** true para versiones de runtime (parche < 100); false para SDK (8.0.427). */
export function isRuntimeBuild(version: string): boolean {
  const patch = parseInt(version.split('.')[2] ?? '0', 10);
  return isNaN(patch) || patch < 100;
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

export type InstalledRuntime = { product: MsrcEntry['product']; version: string };

/**
 * Aplica la política de roll-forward del host de .NET sobre los runtimes instalados.
 * `requested` es la versión mínima solicitada (o "X.Y.0" si solo se conoce el TFM).
 */
export function resolveInstalledRuntime(requested: string, policy: string | undefined, installed: string[]): string | undefined {
  const rp = requested.split('.').map(n => parseInt(n, 10));
  const cands = installed.filter(v => !v.includes('-')).sort(compareVersions);
  const part = (v: string) => v.split('.').map(n => parseInt(n, 10));
  const same = (v: string, n: number) => part(v).slice(0, n).every((x, i) => x === (rp[i] ?? 0));
  const atLeast = (v: string) => compareVersions(v, requested) >= 0;
  const last = (xs: string[]) => xs[xs.length - 1];
  switch ((policy ?? 'Minor').toLowerCase()) {
    case 'disable': return cands.find(v => compareVersions(v, requested) === 0);
    case 'latestpatch': return last(cands.filter(v => same(v, 2) && atLeast(v)));
    case 'latestminor': return last(cands.filter(v => same(v, 1) && atLeast(v)));
    case 'latestmajor': return last(cands.filter(atLeast));
    case 'major': {
      const m = cands.filter(v => same(v, 2) && atLeast(v));
      if (m.length) return last(m);
      const higherMinor = cands.filter(v => same(v, 1) && atLeast(v));
      if (higherMinor.length) { const lowMinor = part(higherMinor[0])[1]; return last(higherMinor.filter(v => part(v)[1] === lowMinor)); }
      const up = cands.filter(atLeast);
      if (!up.length) return undefined;
      const lo = part(up[0]); return last(up.filter(v => part(v)[0] === lo[0] && part(v)[1] === lo[1]));
    }
    default: {   // Minor
      const m = cands.filter(v => same(v, 2) && atLeast(v));
      if (m.length) return last(m);
      const higher = cands.filter(v => same(v, 1) && atLeast(v));
      if (!higher.length) return undefined;
      const lowMinor = part(higher[0])[1];
      return last(higher.filter(v => part(v)[1] === lowMinor));
    }
  }
}

/** Versión efectiva de un runtime y la evidencia que la determina. */
export function effectiveRuntime(t: RuntimeTarget, installed: InstalledRuntime[] | undefined):
  { version?: string; evidence: string; confirmed: boolean } {
  const isApp = t.appKind === 'app';
  if (t.selfContained) {
    return t.version
      ? { version: t.version, evidence: `aplicación autocontenida; versión fijada en ${t.evidence}`, confirmed: isApp }
      : { evidence: 'aplicación autocontenida sin versión de runtime fijada; los runtimes instalados no aplican', confirmed: false };
  }
  const list = (installed ?? []).filter(i => i.product === t.product).map(i => i.version);
  if (!list.length) {
    return { evidence: 'no hay runtimes instalados conocidos (dotnet --list-runtimes no disponible)', confirmed: false };
  }
  const requested = t.version ?? `${t.band}.0`;
  const v = resolveInstalledRuntime(requested, t.rollForward, list);
  if (!v) return { evidence: `ningún runtime instalado satisface ${requested} con roll-forward ${t.rollForward ?? 'Minor'}`, confirmed: false };
  return {
    version: v,
    evidence: `runtime local ${v} (dotnet --list-runtimes, evidencia auxiliar), solicitado ${requested} vía ${t.version ? t.evidence : 'TargetFramework'}, roll-forward ${t.rollForward ?? 'Minor'}`,
    confirmed: isApp,
  };
}

/**
 * Cruza los boletines MSRC con los runtimes detectados en cada aplicación.
 * El hallazgo confirmado exige una aplicación y evidencia de su versión efectiva;
 * bibliotecas, runtimes deducidos o versiones desconocidas quedan "por confirmar".
 */
export function matchMsrc(
  targets: RuntimeTarget[], entries: MsrcEntry[],
  installed: InstalledRuntime[] | undefined,
): Finding[] {
  const out: Finding[] = [];
  for (const t of targets) {
    const eff = effectiveRuntime(t, installed);
    const band = eff.version ? (majorMinor(eff.version) ?? t.band) : t.band;
    const candidates = entries.filter(e => e.product === t.product && e.band === band);
    for (const e of candidates) {
      if (eff.version && e.fixedBuild && compareVersions(eff.version, e.fixedBuild) >= 0) continue;
      const uncertain = !eff.confirmed || !eff.version || !e.fixedBuild;
      out.push({
        id: e.cve,
        aliases: e.kb ? [e.kb] : [],
        source: 'msrc',
        severity: e.severity,
        cvss: e.cvss,
        title: e.title,
        url: `https://msrc.microsoft.com/update-guide/vulnerability/${e.cve}`,
        packageName: `${t.product} ${band}`,
        ecosystem: 'runtime',
        installedVersion: eff.version,
        vulnerableRange: e.fixedBuild ? `< ${e.fixedBuild}` : undefined,
        fixedVersion: e.fixedBuild ?? (e.sdkFixedBuild ? `SDK ${e.sdkFixedBuild}` : undefined),
        uncertain,
        location: t.location,
        direct: true,
        app: t.app,
        evidence: eff.evidence,
      });
    }
  }
  return out;
}
