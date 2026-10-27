import * as vscode from 'vscode';
import { Finding } from '../core/types';

export const SOURCE = 'VulnSync';

/** Asociación diagnóstico → hallazgo, para las acciones rápidas. */
export const findingByDiagnostic = new WeakMap<vscode.Diagnostic, Finding>();

export function toDiagnostics(collection: vscode.DiagnosticCollection, findings: Finding[]) {
  collection.clear();
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const f of findings) {
    const range = new vscode.Range(f.location.line, f.location.startCol, f.location.line, f.location.endCol);
    const fix = f.fixedVersion ? ` Corregido en ${f.fixedVersion}.` : ' Sin versión corregida publicada.';
    const where = f.ecosystem === 'runtime'
      ? `${f.packageName}${f.installedVersion ? ` (${f.installedVersion})` : ''}`
      : `${f.packageName}@${f.installedVersion}${f.direct ? '' : ' (transitiva)'}`;
    const prefix = f.uncertain ? 'Posible vulnerabilidad' : 'Vulnerabilidad';
    const msg = `${prefix} ${f.severity.toUpperCase()} en ${where}: ${f.title}.${fix}` +
      (f.uncertain ? ' La versión exacta no se pudo determinar; confírmala.' : '');
    const d = new vscode.Diagnostic(range, msg, severityOf(f));
    d.source = SOURCE;
    d.code = { value: f.id, target: vscode.Uri.parse(f.url) };
    findingByDiagnostic.set(d, f);
    if (!byFile.has(f.location.file)) byFile.set(f.location.file, []);
    byFile.get(f.location.file)!.push(d);
  }
  for (const [file, diags] of byFile) collection.set(vscode.Uri.file(file), diags);
}

function severityOf(f: Finding): vscode.DiagnosticSeverity {
  if (f.uncertain) return vscode.DiagnosticSeverity.Information;
  switch (f.severity) {
    case 'critical':
    case 'high': return vscode.DiagnosticSeverity.Error;
    case 'medium': return vscode.DiagnosticSeverity.Warning;
    default: return vscode.DiagnosticSeverity.Information;
  }
}
