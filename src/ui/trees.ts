import * as vscode from 'vscode';
import { Finding, ProjectStack, SEVERITY_RANK, Severity } from '../core/types';

const ICONS: Record<Severity, vscode.ThemeIcon> = {
  critical: new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground')),
  high: new vscode.ThemeIcon('error', new vscode.ThemeColor('list.errorForeground')),
  medium: new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground')),
  low: new vscode.ThemeIcon('info'),
  unknown: new vscode.ThemeIcon('question'),
};

type FindingNode = { kind: 'group'; label: string; items: Finding[] } | { kind: 'finding'; f: Finding };

export class FindingsTree implements vscode.TreeDataProvider<FindingNode> {
  private emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;
  private findings: Finding[] = [];

  set(findings: Finding[]) { this.findings = findings; this.emitter.fire(); }

  getChildren(node?: FindingNode): FindingNode[] {
    if (!node) {
      const groups = new Map<string, Finding[]>();
      for (const f of this.findings) {
        const key = f.ecosystem === 'runtime' ? f.packageName : `${f.packageName}@${f.installedVersion}`;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key)!.push(f);
      }
      return [...groups].map(([label, items]) => ({ kind: 'group' as const, label, items }));
    }
    return node.kind === 'group' ? node.items.map(f => ({ kind: 'finding' as const, f })) : [];
  }

  getTreeItem(node: FindingNode): vscode.TreeItem {
    if (node.kind === 'group') {
      const worst = node.items.reduce<Severity>((w, f) => SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w, 'unknown');
      const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.Expanded);
      const fixes = node.items.map(f => f.fixedVersion).filter(Boolean) as string[];
      item.description = `${node.items.length} · ${node.items[0].ecosystem}${node.items[0].direct ? '' : ' · transitiva'}`;
      item.tooltip = fixes.length ? `Versiones corregidas: ${[...new Set(fixes)].join(', ')}` : undefined;
      item.iconPath = ICONS[worst];
      return item;
    }
    const f = node.f;
    const item = new vscode.TreeItem(`${f.id}${f.uncertain ? ' (por confirmar)' : ''}`, vscode.TreeItemCollapsibleState.None);
    item.description = `${f.severity}${f.cvss ? ` · CVSS ${f.cvss}` : ''}${f.fixedVersion ? ` → ${f.fixedVersion}` : ''} · ${f.source === 'msrc' ? 'MSRC' : 'GitHub'}`;
    item.tooltip = new vscode.MarkdownString(
      `**${f.title}**\n\n${[f.id, ...f.aliases].join(' · ')}\n\nInstalada: \`${f.installedVersion ?? 'desconocida'}\`` +
      (f.vulnerableRange ? ` · Rango vulnerable: \`${f.vulnerableRange}\`` : '') +
      (f.fixedVersion ? `\n\nCorregida en: \`${f.fixedVersion}\`` : ''));
    item.iconPath = ICONS[f.severity];
    item.contextValue = 'finding';
    item.command = {
      title: 'Ir a la dependencia', command: 'vscode.open',
      arguments: [vscode.Uri.file(f.location.file), {
        selection: new vscode.Range(f.location.line, f.location.startCol, f.location.line, f.location.endCol),
      }],
    };
    return item;
  }
}

type StackNode = { label: string; description?: string; icon: string; children?: StackNode[]; file?: string };

export class StackTree implements vscode.TreeDataProvider<StackNode> {
  private emitter = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.emitter.event;
  private roots: StackNode[] = [];

  set(stack: ProjectStack, root: string) {
    const rel = (p: string) => p.startsWith(root) ? p.slice(root.length + 1) : p;
    const names: Record<string, string> = { npm: 'Node.js / npm', nuget: '.NET / NuGet', pip: 'Python / PyPI' };
    this.roots = stack.ecosystems.map(eco => {
      const deps = stack.dependencies.filter(d => d.ecosystem === eco);
      const children: StackNode[] = [
        { label: 'Dependencias', description: `${deps.filter(d => d.direct).length} directas · ${deps.filter(d => !d.direct).length} transitivas`, icon: 'package' },
        { label: 'Sin versión exacta', description: `${deps.filter(d => d.approximate || !d.version).length}`, icon: 'question' },
      ];
      if (eco === 'nuget') {
        for (const r of uniq(stack.runtimes.map(r => `${r.product} ${r.band}${r.version ? ` (${r.version})` : ''}`))) {
          children.push({ label: r, icon: 'server-environment', description: 'runtime · MSRC' });
        }
      }
      return { label: names[eco], icon: 'layers', children };
    });
    if (stack.manifests.length) {
      this.roots.push({
        label: 'Manifiestos', icon: 'files', description: `${uniq(stack.manifests).length}`,
        children: uniq(stack.manifests).map(m => ({ label: rel(m), icon: 'file', file: m })),
      });
    }
    this.emitter.fire();
  }

  getChildren(n?: StackNode) { return n ? n.children ?? [] : this.roots; }
  getTreeItem(n: StackNode) {
    const item = new vscode.TreeItem(n.label, n.children?.length ? vscode.TreeItemCollapsibleState.Expanded : vscode.TreeItemCollapsibleState.None);
    item.description = n.description;
    item.iconPath = new vscode.ThemeIcon(n.icon);
    if (n.file) item.command = { title: 'Abrir', command: 'vscode.open', arguments: [vscode.Uri.file(n.file)] };
    return item;
  }
}

const uniq = <T>(xs: T[]) => [...new Set(xs)];
