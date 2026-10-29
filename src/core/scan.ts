import { Finding, ProjectStack, SEVERITY_RANK, Severity, SourceState, SourceStatus } from './types';
import { classifyDependency, FetchLike, matchGithubAdvisories, queryGithubAdvisories, queryItem, queryKey } from './sources/github';
import { describeMsrcStatus, InstalledRuntime, MsrcCache, matchMsrc } from './sources/msrc';
import { codeSpan, escapeMd, mdLink, relativeToRoots, RootFolder } from './text';

export interface ScanOptions {
  fetch: FetchLike;
  githubToken?: string;
  msrcCache?: MsrcCache;
  /** Error de la última sincronización MSRC (si falló). */
  msrcSyncError?: string;
  /** MSRC deshabilitado por configuración. */
  msrcDisabled?: boolean;
  installedRuntimes?: InstalledRuntime[];
  minimumSeverity: Severity;
  ignored: string[];
  signal?: AbortSignal;
  onProgress?: (msg: string) => void;
  /** Reloj inyectable para pruebas. */
  now?: () => number;
}

export interface ScanResult {
  /** Versión del formato (para descartar resultados persistidos antiguos). */
  schema: 2;
  findings: Finding[];
  /** Dependencias cuya consulta a GitHub terminó correctamente. */
  checkedDependencies: number;
  /** Dependencias sin versión ni rango interpretable: no se pueden verificar. */
  unverifiedDependencies: number;
  /** Dependencias cuyo lote de consulta falló. */
  failedDependencies: number;
  sources: SourceStatus[];
  /** true solo si ninguna fuente necesaria falló, está parcial o proviene de caché. */
  complete: boolean;
  scannedAt: string;
  errors: string[];
}

export const STATE_LABEL: Record<SourceState, string> = {
  complete: 'completa', partial: 'parcial', cached: 'datos en caché', failed: 'falló', notApplicable: 'no aplica',
};
const SOURCE_LABEL = { github: 'GitHub Advisory', msrc: 'MSRC' } as const;

export const isComplete = (sources: SourceStatus[]) =>
  sources.every(s => s.state === 'complete' || s.state === 'notApplicable');

/** Descripción corta de las fuentes que impiden considerar el escaneo completo. */
export function incompleteSummary(r: ScanResult): string {
  return r.sources
    .filter(s => s.state !== 'complete' && s.state !== 'notApplicable')
    .map(s => `${SOURCE_LABEL[s.source]}: ${STATE_LABEL[s.state]}${s.detail ? ` — ${s.detail}` : ''}`)
    .join('\n');
}

export async function scanStack(stack: ProjectStack, opts: ScanOptions): Promise<ScanResult> {
  const errors: string[] = [];
  let findings: Finding[] = [];
  const sources: SourceStatus[] = [];
  const now = opts.now ?? Date.now;

  // ---- GitHub Advisory ----
  const queryable = stack.dependencies.filter(d => classifyDependency(d) !== 'unverified');
  const unverified = stack.dependencies.length - queryable.length;
  let checkedDeps: typeof queryable = [];
  if (queryable.length) {
    opts.onProgress?.(`Consultando GitHub Advisory Database (${queryable.length} paquetes)…`);
    try {
      const r = await queryGithubAdvisories(queryable, {
        fetch: opts.fetch, token: opts.githubToken, signal: opts.signal,
        onProgress: (d, t) => opts.onProgress?.(`GitHub Advisory: lote ${d}/${t}`),
      });
      checkedDeps = queryable.filter(d => r.checked.has(queryKey(d.ecosystem, queryItem(d)!)));
      findings.push(...matchGithubAdvisories(checkedDeps, r.advisories));
      errors.push(...r.errors);
      const failed = queryable.length - checkedDeps.length;
      const state: SourceState = failed === 0 ? 'complete' : checkedDeps.length === 0 ? 'failed' : 'partial';
      sources.push({
        source: 'github', state,
        detail: failed
          ? `${failed} de ${queryable.length} dependencias sin consultar: ${r.errors.join('; ') || 'error desconocido'}`
          : undefined,
      });
    } catch (e: any) {
      if (e?.name === 'AbortError') throw e;
      const msg = e?.message ?? String(e);
      errors.push(msg);
      sources.push({ source: 'github', state: 'failed', detail: msg });
    }
  } else {
    sources.push({ source: 'github', state: 'notApplicable', detail: 'Sin dependencias verificables' });
  }

  // ---- MSRC ----
  if (!stack.runtimes.length) {
    sources.push({ source: 'msrc', state: 'notApplicable', detail: 'Sin runtimes .NET en el proyecto' });
  } else if (opts.msrcDisabled) {
    sources.push({ source: 'msrc', state: 'notApplicable', detail: 'Deshabilitado en la configuración' });
  } else {
    if (opts.msrcSyncError) errors.push(`MSRC: ${opts.msrcSyncError}`);
    const st = describeMsrcStatus(opts.msrcCache, opts.msrcSyncError, now());
    sources.push(st);
    if (opts.msrcCache && st.state !== 'failed') {
      const entries = Object.values(opts.msrcCache.docs).flatMap(d => d.entries);
      findings.push(...matchMsrc(stack.runtimes, entries, opts.installedRuntimes));
    }
  }

  const ignored = new Set(opts.ignored.map(s => s.toUpperCase()));
  const min = SEVERITY_RANK[opts.minimumSeverity] ?? 0;
  findings = findings.filter(f =>
    !ignored.has(f.id.toUpperCase()) && !f.aliases.some(a => ignored.has(a.toUpperCase())) &&
    (f.severity === 'unknown' || SEVERITY_RANK[f.severity] >= min));

  // Un mismo CVE puede llegar por GHSA y por MSRC: se conserva uno por ubicación.
  const seen = new Set<string>();
  findings = findings.filter(f => {
    const ids = [f.id, ...f.aliases].filter(x => /^CVE-/i.test(x));
    const key = `${ids[0] ?? f.id}|${f.packageName.toLowerCase()}|${f.location.file}|${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  findings.sort((a, b) =>
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    Number(a.uncertain) - Number(b.uncertain) ||
    a.packageName.localeCompare(b.packageName));

  return {
    schema: 2,
    findings,
    checkedDependencies: checkedDeps.length,
    unverifiedDependencies: unverified,
    failedDependencies: queryable.length - checkedDeps.length,
    sources,
    complete: isComplete(sources),
    scannedAt: new Date(now()).toISOString(),
    errors,
  };
}

/** Celda de tabla Markdown: texto externo siempre escapado. */
const cell = (s: string | undefined) => escapeMd(s ?? '—');

/** Reporte en Markdown, útil para adjuntar a un PR o ticket. */
export function renderMarkdownReport(stack: ProjectStack, r: ScanResult, roots: RootFolder[] | string): string {
  const rel = (p: string) => relativeToRoots(p, roots);
  const count = (s: Severity) => r.findings.filter(f => f.severity === s && !f.uncertain).length;
  const lines: string[] = [];
  lines.push('# Reporte de vulnerabilidades — VulnSync', '');
  lines.push(`Generado: ${new Date(r.scannedAt).toLocaleString()}`, '');
  if (!r.complete) {
    lines.push('> ⚠️ **ESCANEO INCOMPLETO.** Que no aparezcan hallazgos NO demuestra que el proyecto esté limpio.', '');
  }
  lines.push(`**Stack detectado:** ${escapeMd(stack.ecosystems.join(', ') || 'ninguno')}` +
    (stack.runtimes.length ? ` · runtimes: ${escapeMd([...new Set(stack.runtimes.map(t => `${t.product} ${t.band}`))].join(', '))}` : ''), '');
  if (stack.sdks?.length) {
    lines.push(`SDK fijado (informativo, no se evalúa como runtime): ${escapeMd(stack.sdks.map(s => s.version).join(', '))}`, '');
  }
  lines.push('## Estado de las fuentes', '', '| Fuente | Estado | Detalle |', '|---|---|---|');
  for (const s of r.sources) {
    lines.push(`| ${SOURCE_LABEL[s.source]} | ${STATE_LABEL[s.state]} | ${cell(s.detail)}${s.dataAsOf ? ` (datos de ${escapeMd(s.dataAsOf.slice(0, 10))})` : ''} |`);
  }
  lines.push('');
  lines.push(`Dependencias verificadas: ${r.checkedDependencies} · sin consultar por error: ${r.failedDependencies} · sin versión ni rango interpretable: ${r.unverifiedDependencies}`, '');
  lines.push('| Crítica | Alta | Media | Baja | Por confirmar |', '|---|---|---|---|---|');
  lines.push(`| ${count('critical')} | ${count('high')} | ${count('medium')} | ${count('low')} | ${r.findings.filter(f => f.uncertain).length} |`, '');
  if (!r.findings.length) {
    lines.push(r.complete
      ? '✅ No se encontraron vulnerabilidades conocidas.'
      : '⚠️ No se obtuvieron hallazgos, pero el escaneo está incompleto: no se puede afirmar que no existan.');
    return lines.join('\n');
  }
  lines.push('| Severidad | ID | Paquete | Instalada / rango | Corregida en | Fuente | Archivo |', '|---|---|---|---|---|---|---|');
  for (const f of r.findings) {
    const where = f.installedVersion ?? (f.declaredRange ? `rango ${f.declaredRange}` : undefined);
    lines.push(`| ${f.severity}${f.uncertain ? ' (?)' : ''} | ${mdLink(f.id, f.url)} | ${cell(f.packageName)}${f.direct ? '' : ' _(transitiva)_'} | ` +
      `${cell(where)} | ${cell(f.fixedVersion)} | ${f.source === 'msrc' ? 'MSRC' : 'GitHub'} | ` +
      `${codeSpan(`${rel(f.location.file)}:${f.location.line + 1}`).replace(/\|/g, '\\|')} |`);
  }
  const rt = r.findings.filter(f => f.ecosystem === 'runtime' && f.evidence);
  if (rt.length) {
    lines.push('', '## Evidencia de runtime', '');
    for (const f of rt) lines.push(`- ${escapeMd(f.id)} — aplicación ${codeSpan(f.app ?? '—')}: ${escapeMd(f.evidence!)}`);
  }
  lines.push('', '_(?) = la versión efectiva no se pudo determinar con certeza (rango sin lockfile, runtime sin evidencia); confirma manualmente._');
  return lines.join('\n');
}
