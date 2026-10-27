import { Finding, ProjectStack, SEVERITY_RANK, Severity } from './types';
import { FetchLike, matchGithubAdvisories, queryGithubAdvisories } from './sources/github';
import { MsrcCache, matchMsrc, MsrcEntry } from './sources/msrc';

export interface ScanOptions {
  fetch: FetchLike;
  githubToken?: string;
  msrcCache?: MsrcCache;
  installedRuntimes?: { product: MsrcEntry['product']; version: string }[];
  minimumSeverity: Severity;
  ignored: string[];
  signal?: AbortSignal;
  onProgress?: (msg: string) => void;
}

export interface ScanResult {
  findings: Finding[];
  checkedDependencies: number;
  uncheckedDependencies: number;
  scannedAt: string;
  errors: string[];
}

export async function scanStack(stack: ProjectStack, opts: ScanOptions): Promise<ScanResult> {
  const errors: string[] = [];
  let findings: Finding[] = [];

  const withVersion = stack.dependencies.filter(d => d.version);
  if (withVersion.length) {
    try {
      opts.onProgress?.(`Consultando GitHub Advisory Database (${withVersion.length} paquetes)…`);
      const adv = await queryGithubAdvisories(withVersion, {
        fetch: opts.fetch, token: opts.githubToken, signal: opts.signal,
        onProgress: (d, t) => opts.onProgress?.(`GitHub Advisory: lote ${d}/${t}`),
      });
      findings.push(...matchGithubAdvisories(withVersion, adv));
    } catch (e: any) {
      if (e?.name === 'AbortError') throw e;
      errors.push(e?.message ?? String(e));
    }
  }

  if (opts.msrcCache && stack.runtimes.length) {
    const entries = Object.values(opts.msrcCache.docs).flatMap(d => d.entries);
    findings.push(...matchMsrc(stack.runtimes, entries, opts.installedRuntimes));
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
    findings,
    checkedDependencies: withVersion.length,
    uncheckedDependencies: stack.dependencies.length - withVersion.length,
    scannedAt: new Date().toISOString(),
    errors,
  };
}

/** Reporte en Markdown, útil para adjuntar a un PR o ticket. */
export function renderMarkdownReport(stack: ProjectStack, r: ScanResult, root: string): string {
  const rel = (p: string) => p.startsWith(root) ? p.slice(root.length).replace(/^[\\/]/, '') : p;
  const count = (s: Severity) => r.findings.filter(f => f.severity === s && !f.uncertain).length;
  const lines: string[] = [];
  lines.push('# Reporte de vulnerabilidades — VulnSync', '');
  lines.push(`Generado: ${new Date(r.scannedAt).toLocaleString()}`, '');
  lines.push(`**Stack detectado:** ${stack.ecosystems.join(', ') || 'ninguno'}` +
    (stack.runtimes.length ? ` · runtimes: ${[...new Set(stack.runtimes.map(t => `${t.product} ${t.band}`))].join(', ')}` : ''), '');
  lines.push(`Dependencias verificadas: ${r.checkedDependencies} · sin versión determinable: ${r.uncheckedDependencies}`, '');
  lines.push('| Crítica | Alta | Media | Baja | Por confirmar |', '|---|---|---|---|---|');
  lines.push(`| ${count('critical')} | ${count('high')} | ${count('medium')} | ${count('low')} | ${r.findings.filter(f => f.uncertain).length} |`, '');
  if (r.errors.length) lines.push('> ⚠️ ' + r.errors.join('\n> ⚠️ '), '');
  if (!r.findings.length) { lines.push('✅ No se encontraron vulnerabilidades conocidas.'); return lines.join('\n'); }
  lines.push('| Severidad | ID | Paquete | Instalada | Corregida en | Fuente | Archivo |', '|---|---|---|---|---|---|---|');
  for (const f of r.findings) {
    lines.push(`| ${f.severity}${f.uncertain ? ' (?)' : ''} | [${f.id}](${f.url}) | ${f.packageName}${f.direct ? '' : ' _(transitiva)_'} | ` +
      `${f.installedVersion ?? '—'} | ${f.fixedVersion ?? '—'} | ${f.source === 'msrc' ? 'MSRC' : 'GitHub'} | ` +
      `${rel(f.location.file)}:${f.location.line + 1} |`);
  }
  lines.push('', '_(?) = la versión exacta no se pudo determinar (sin lockfile o sin runtime instalado); confirma manualmente._');
  return lines.join('\n');
}
