import * as vscode from 'vscode';
import { findingByDiagnostic, SOURCE } from './diagnostics';
import { Finding } from '../core/types';
import { planUpgrade, UpgradePlan } from '../core/fix';

/** Acciones rápidas: subir a la versión corregida, abrir el boletín, ignorar. */
export class VulnCodeActions implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(doc: vscode.TextDocument, _range: vscode.Range, ctx: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diag of ctx.diagnostics) {
      if (diag.source !== SOURCE) continue;
      const f = findingByDiagnostic.get(diag);
      if (!f) continue;

      const plan = upgradePlan(doc, diag.range, f);
      if (plan?.kind === 'edit') {
        const a = new vscode.CodeAction(`Actualizar ${f.packageName} a ${f.fixedVersion}`, vscode.CodeActionKind.QuickFix);
        a.edit = new vscode.WorkspaceEdit();
        // needsConfirmation: VS Code muestra una vista previa del cambio antes de aplicarlo.
        a.edit.replace(doc.uri, diag.range, plan.text, {
          label: `${f.packageName}: ${doc.getText(diag.range)} → ${plan.text}`, needsConfirmation: true,
        });
        a.diagnostics = [diag];
        a.isPreferred = true;
        actions.push(a);
      } else if (plan?.kind === 'suggest') {
        const a = new vscode.CodeAction(`Sugerencia: ${f.packageName} ≥ ${f.fixedVersion} (editar manualmente)`, vscode.CodeActionKind.QuickFix);
        a.command = { title: 'Ver sugerencia', command: 'vulnsync.suggestFix', arguments: [f.packageName, f.fixedVersion, plan.reason] };
        a.diagnostics = [diag];
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

/** Plan de actualización según el manifiesto; nunca amplía el rango original. */
function upgradePlan(doc: vscode.TextDocument, range: vscode.Range, f: Finding): UpgradePlan | undefined {
  if (!f.fixedVersion || !f.direct || f.ecosystem === 'runtime') return undefined;
  const file = doc.fileName.toLowerCase();
  const current = doc.getText(range);
  const ok =
    (f.ecosystem === 'npm' && file.endsWith('package.json')) ||
    (f.ecosystem === 'nuget' && /\.(cs|fs|vb)proj$|\.props$/.test(file)) ||
    (f.ecosystem === 'pip' && (/requirements.*\.txt$/.test(file) || file.endsWith('pyproject.toml') || file.endsWith('pipfile')));
  return ok ? planUpgrade(f.ecosystem, current, f.fixedVersion) : undefined;
}
