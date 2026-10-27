import * as vscode from 'vscode';
import { findingByDiagnostic, SOURCE } from './diagnostics';
import { Finding } from '../core/types';

/** Acciones rápidas: subir a la versión corregida, abrir el boletín, ignorar. */
export class VulnCodeActions implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of ctx.diagnostics) {
      if (diag.source !== SOURCE) continue;
      const f = findingByDiagnostic.get(diag);
      if (!f) continue;

      const edit = upgradeEdit(doc, diag.range, f);
      if (edit) {
        const a = new vscode.CodeAction(`Actualizar ${f.packageName} a ${f.fixedVersion}`, vscode.CodeActionKind.QuickFix);
        a.edit = new vscode.WorkspaceEdit();
        a.edit.replace(doc.uri, diag.range, edit);
        a.diagnostics = [diag];
        a.isPreferred = true;
        actions.push(a);
      }
      if (f.ecosystem === 'runtime') {
        const a = new vscode.CodeAction(`Descargar ${f.packageName}${f.fixedVersion ? ` (≥ ${f.fixedVersion})` : ''}`, vscode.CodeActionKind.QuickFix);
        const band = f.packageName.split(' ').pop();
        a.command = { title: 'Descargar', command: 'vscode.open', arguments: [vscode.Uri.parse(`https://dotnet.microsoft.com/download/dotnet/${band}`)] };
        a.diagnostics = [diag];
        actions.push(a);
      }
      const open = new vscode.CodeAction(`Abrir boletín ${f.id}`, vscode.CodeActionKind.QuickFix);
      open.command = { title: 'Abrir', command: 'vscode.open', arguments: [vscode.Uri.parse(f.url)] };
      actions.push(open);

      const ignore = new vscode.CodeAction(`Ignorar ${f.id} en este proyecto`, vscode.CodeActionKind.QuickFix);
      ignore.command = { title: 'Ignorar', command: 'vulnsync.ignore', arguments: [f] };
      actions.push(ignore);
    }
    return actions;
  }
}

/** Texto de reemplazo para la versión declarada, según el tipo de manifiesto. */
function upgradeEdit(doc: vscode.TextDocument, range: vscode.Range, f: Finding): string | undefined {
  if (!f.fixedVersion || !f.direct || f.ecosystem === 'runtime') return undefined;
  const file = doc.fileName.toLowerCase();
  const current = doc.getText(range);
  if (f.ecosystem === 'npm' && file.endsWith('package.json')) {
    const prefix = /^[\^~]/.exec(current)?.[0] ?? (/^[<>=]/.test(current) ? '^' : '');
    return prefix + f.fixedVersion;
  }
  if (f.ecosystem === 'nuget' && /\.(cs|fs|vb)proj$|\.props$/.test(file)) {
    return /^\[.*\]$/.test(current) ? `[${f.fixedVersion}]` : f.fixedVersion;
  }
  if (f.ecosystem === 'pip' && (/requirements.*\.txt$/.test(file) || file.endsWith('pyproject.toml'))) {
    if (/^[\^~]?\d/.test(current)) return (/^[\^~]/.exec(current)?.[0] ?? '') + f.fixedVersion; // poetry
    return current.startsWith('==') ? `==${f.fixedVersion}` : `>=${f.fixedVersion}`;
  }
  return undefined;
}
