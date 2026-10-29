import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { detectStack, MANIFEST_GLOB, ProjectFile, RUNTIMECONFIG_GLOB } from './core/detect';
import { incompleteSummary, renderMarkdownReport, scanStack, ScanResult } from './core/scan';
import { RootFolder } from './core/text';
import { FetchLike } from './core/sources/github';
import { MsrcCache, msrcNeedsSync, parseDotnetListRuntimes, syncMsrc } from './core/sources/msrc';
import { Ecosystem, Finding, ProjectStack, Severity } from './core/types';
import { toDiagnostics } from './ui/diagnostics';
import { VulnCodeActions } from './ui/codeActions';
import { FindingsTree, StackTree } from './ui/trees';

let output: vscode.OutputChannel;
let statusBar: vscode.StatusBarItem;
let diagnostics: vscode.DiagnosticCollection;
let findingsTree: FindingsTree;
let stackTree: StackTree;
let ctx: vscode.ExtensionContext;

let lastStack: ProjectStack | undefined;
let lastResult: ScanResult | undefined;
let running: Promise<void> | undefined;
let rerun = false;
let debounce: NodeJS.Timeout | undefined;
let rateLimitWarned = false;
let fetchImpl: FetchLike | undefined;   // solo se sustituye en modo de pruebas

const MAX_FILE_BYTES = 25 * 1024 * 1024;
const cfg = () => vscode.workspace.getConfiguration('vulnsync');

export function activate(context: vscode.ExtensionContext) {
  ctx = context;
  output = vscode.window.createOutputChannel('VulnSync');
  diagnostics = vscode.languages.createDiagnosticCollection('vulnsync');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBar.command = 'workbench.view.extension.vulnsync';
  findingsTree = new FindingsTree();
  stackTree = new StackTree();

  context.subscriptions.push(
    output, diagnostics, statusBar,
    vscode.window.registerTreeDataProvider('vulnsync.findings', findingsTree),
    vscode.window.registerTreeDataProvider('vulnsync.stack', stackTree),
    vscode.languages.registerCodeActionsProvider(
      [{ pattern: '**/package.json' }, { pattern: '**/*.{csproj,fsproj,vbproj,props}' },
       { pattern: '**/requirements*.txt' }, { pattern: '**/pyproject.toml' }, { pattern: '**/Pipfile' },
       { pattern: '**/*.lock' }, { pattern: '**/*lock.json' }, { pattern: '**/pnpm-lock.yaml' }, { pattern: '**/global.json' }],
      new VulnCodeActions(), { providedCodeActionKinds: VulnCodeActions.kinds }),

    vscode.commands.registerCommand('vulnsync.scan', () => requestScan({ interactive: true })),
    vscode.commands.registerCommand('vulnsync.sync', () => requestScan({ interactive: true, forceMsrc: true })),
    vscode.commands.registerCommand('vulnsync.report', showReport),
    vscode.commands.registerCommand('vulnsync.signIn', signIn),
    vscode.commands.registerCommand('vulnsync.clearCache', clearCache),
    vscode.commands.registerCommand('vulnsync.suggestFix', (pkg: string, fixed: string, reason: string) =>
      vscode.window.showInformationMessage(`VulnSync: ${pkg} → versión corregida ${fixed}. ${reason}`)),
    vscode.commands.registerCommand('vulnsync.ignore', ignoreFinding),
    vscode.commands.registerCommand('vulnsync.openAdvisory', (n: any) => {
      const f: Finding | undefined = n?.f ?? n;
      if (f?.url) vscode.env.openExternal(vscode.Uri.parse(f.url));
    }),
    vscode.workspace.onDidChangeConfiguration(e => { if (e.affectsConfiguration('vulnsync')) { schedule(); scheduleScan(1500); } }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => scheduleScan(1500)),
  );

  const watcher = vscode.workspace.createFileSystemWatcher(MANIFEST_GLOB);
  watcher.onDidChange(() => scheduleScan());
  watcher.onDidCreate(() => scheduleScan());
  watcher.onDidDelete(() => scheduleScan());
  context.subscriptions.push(watcher);

  // Mostrar los resultados de la sesión anterior mientras corre el primer escaneo.
  const cached = context.workspaceState.get<{ stack: ProjectStack; result: ScanResult }>('lastScan');
  if (cached?.result?.schema === 2) applyResult(cached.stack, cached.result);   // formatos antiguos se descartan

  setStatus('$(sync~spin) VulnSync', 'Escaneando…');
  statusBar.show();
  schedule();
  scheduleScan(2000);

  // En pruebas de integración se expone una API mínima con red inyectable.
  if (context.extensionMode === vscode.ExtensionMode.Test) {
    return {
      setFetch: (f: FetchLike | undefined) => { fetchImpl = f; },
      scan: async () => { await requestScan({ interactive: false }); return lastResult; },
      getState: () => ({ result: lastResult, stack: lastStack, status: statusBar.text, tooltip: String(statusBar.tooltip ?? '') }),
      diagnosticCount: () => { let n = 0; diagnostics.forEach((_u, d) => { n += d.length; }); return n; },
    };
  }
}

export function deactivate() { /* recursos liberados vía subscriptions */ }

// ---------------- Programación ----------------

let interval: NodeJS.Timeout | undefined;
function schedule() {
  if (interval) clearInterval(interval);
  const hours = Math.max(1, cfg().get<number>('syncIntervalHours', 12));
  interval = setInterval(() => requestScan({ interactive: false }), hours * 3600_000);
  ctx.subscriptions.push({ dispose: () => interval && clearInterval(interval) });
}

function scheduleScan(delay = 3000) {
  if (debounce) clearTimeout(debounce);
  debounce = setTimeout(() => requestScan({ interactive: false }), delay);
}

async function requestScan(o: { interactive: boolean; forceMsrc?: boolean }) {
  if (running) { rerun = true; return running; }
  running = (async () => {
    try {
      await vscode.window.withProgress(
        { location: o.interactive ? vscode.ProgressLocation.Notification : vscode.ProgressLocation.Window, title: 'VulnSync', cancellable: o.interactive },
        (progress, token) => runScan(o, (m) => progress.report({ message: m }), token));
    } catch (e: any) {
      if (e?.name !== 'AbortError') {
        output.appendLine(`[error] ${e?.stack ?? e}`);
        if (o.interactive) vscode.window.showErrorMessage(`VulnSync: ${e?.message ?? e}`);
      }
      setStatus('$(shield) VulnSync', 'El último escaneo falló. Ver salida "VulnSync".');
    } finally {
      running = undefined;
      if (rerun) { rerun = false; scheduleScan(500); }
    }
  })();
  return running;
}

// ---------------- Escaneo ----------------

async function runScan(o: { interactive: boolean; forceMsrc?: boolean }, report: (m: string) => void, token: vscode.CancellationToken) {
  const abort = new AbortController();
  token.onCancellationRequested(() => abort.abort());
  setStatus('$(sync~spin) VulnSync', 'Escaneando…');

  report('Detectando stack del proyecto…');
  const files = await readManifests();
  const stack = detectStack(files, {
    ecosystems: cfg().get<Ecosystem[]>('ecosystems', ['nuget', 'npm', 'pip']),
    includeTransitive: cfg().get<boolean>('includeTransitive', true),
  });
  annotateWorkspaces(stack);
  output.appendLine(`Stack: ${stack.ecosystems.join(', ') || '—'} · ${stack.dependencies.length} dependencias · runtimes: ` +
    (stack.runtimes.map(r => `${r.product} ${r.band}`).join(', ') || '—'));

  // MSRC solo si hay runtimes .NET en el proyecto.
  let msrcCache: MsrcCache | undefined;
  let msrcSyncError: string | undefined;
  let installed: ReturnType<typeof parseDotnetListRuntimes> | undefined;
  const msrcEnabled = cfg().get<boolean>('msrc.enabled', true);
  if (msrcEnabled && stack.runtimes.length) {
    msrcCache = await loadMsrcCache();
    const maxAge = cfg().get<number>('syncIntervalHours', 12) * 3600_000;
    if (o.forceMsrc || msrcNeedsSync(msrcCache, Date.now(), maxAge)) {
      try {
        report('Sincronizando boletines de Microsoft (MSRC)…');
        const r = await syncMsrc(httpFetch, msrcCache, cfg().get<number>('msrc.monthsToSync', 12), { signal: abort.signal, onProgress: report });
        msrcCache = r.cache;
        await saveMsrcCache(msrcCache);
        output.appendLine(`MSRC: ${Object.keys(msrcCache.docs).length} boletines en caché, ${r.downloaded} descargados.`);
        for (const f of r.failed) output.appendLine(`[warn] MSRC ${f.id} no se pudo actualizar (intento ${f.attempts}, reintento tras ${f.nextRetryAt}): ${f.error}`);
      } catch (e: any) {
        if (e?.name === 'AbortError') throw e;
        msrcSyncError = e?.message ?? String(e);
        output.appendLine(`[warn] MSRC no disponible, se usa la caché si existe: ${msrcSyncError}`);
      }
    }
    // Un proceso externo solo se ejecuta en workspaces de confianza.
    if (vscode.workspace.isTrusted && cfg().get<boolean>('msrc.checkInstalledRuntimes', true)) installed = await listInstalledRuntimes();
  }

  const result = await scanStack(stack, {
    fetch: httpFetch,
    githubToken: await githubToken(),
    msrcCache, msrcSyncError, msrcDisabled: !msrcEnabled,
    installedRuntimes: installed,
    minimumSeverity: cfg().get<Severity>('minimumSeverity', 'low'),
    ignored: cfg().get<string[]>('ignoredAdvisories', []),
    signal: abort.signal,
    onProgress: report,
  });

  for (const err of result.errors) {
    output.appendLine(`[warn] ${err}`);
  }
  if (result.errors.some(e => /Límite/.test(e)) && !rateLimitWarned) {
    rateLimitWarned = true;
    vscode.window.showWarningMessage(
      'VulnSync: se alcanzó el límite de la API de GitHub (60 peticiones/hora sin sesión).',
      'Iniciar sesión en GitHub').then(c => c && signIn());
  }

  applyResult(stack, result);
  await ctx.workspaceState.update('lastScan', { stack, result });

  const real = result.findings.filter(f => !f.uncertain);
  output.appendLine(`Escaneo terminado${result.complete ? '' : ' (INCOMPLETO)'}: ${real.length} vulnerabilidades, ${result.findings.length - real.length} por confirmar.`);
  if (!result.complete) output.appendLine(`[warn] Escaneo incompleto:\n${incompleteSummary(result)}`);
  if (o.interactive) {
    if (!result.complete) {
      vscode.window.showWarningMessage(
        `VulnSync: escaneo INCOMPLETO. ${real.length ? `${real.length} vulnerabilidad(es) confirmadas, pero faltan fuentes.` : 'Sin hallazgos, pero esto NO significa que el proyecto esté limpio.'}\n${incompleteSummary(result)}`,
        'Ver reporte').then(c => c && showReport());
    } else {
      const msg = real.length
        ? `VulnSync: ${real.length} vulnerabilidad(es) encontradas.`
        : result.findings.length ? `VulnSync: sin vulnerabilidades confirmadas (${result.findings.length} por confirmar).`
        : 'VulnSync: no se encontraron vulnerabilidades conocidas.';
      vscode.window.showInformationMessage(msg, 'Ver reporte').then(c => c && showReport());
    }
  }
}

function applyResult(stack: ProjectStack, result: ScanResult) {
  lastStack = stack;
  lastResult = result;
  toDiagnostics(diagnostics, result.findings);
  findingsTree.set(result.findings, result);
  stackTree.set(stack, rootFolders());

  const real = result.findings.filter(f => !f.uncertain);
  const severe = real.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  const warnBg = new vscode.ThemeColor('statusBarItem.warningBackground');
  if (!stack.dependencies.length && !stack.runtimes.length) {
    setStatus('$(shield) VulnSync', 'No se detectó un stack compatible (.NET, Node.js, Python).');
    statusBar.backgroundColor = undefined;
  } else if (!result.complete) {
    // Nunca verde ni "pass" cuando falta una fuente necesaria.
    setStatus(real.length ? `$(shield) ${real.length} · incompleto` : '$(warning) VulnSync: incompleto',
      `Escaneo incompleto: el resultado NO demuestra que el proyecto esté limpio.\n${incompleteSummary(result)}`);
    statusBar.backgroundColor = severe ? new vscode.ThemeColor('statusBarItem.errorBackground') : warnBg;
  } else if (!real.length) {
    setStatus('$(pass) VulnSync', `Sin vulnerabilidades confirmadas · ${result.checkedDependencies} dependencias verificadas` +
      (result.unverifiedDependencies ? ` · ${result.unverifiedDependencies} sin verificar` : ''));
    statusBar.backgroundColor = undefined;
  } else {
    setStatus(`$(shield) ${real.length}`, `${real.length} vulnerabilidades (${severe} críticas/altas). Clic para ver detalles.`);
    statusBar.backgroundColor = new vscode.ThemeColor(severe ? 'statusBarItem.errorBackground' : 'statusBarItem.warningBackground');
  }
}

function setStatus(text: string, tooltip: string) {
  statusBar.text = text;
  statusBar.tooltip = tooltip;
}

async function readManifests(): Promise<ProjectFile[]> {
  const exclude = cfg().get<string[]>('exclude', []);
  const uris = await vscode.workspace.findFiles(MANIFEST_GLOB, exclude.length ? `{${exclude.join(',')}}` : undefined, 5000);
  const out: ProjectFile[] = [];
  const decoder = new TextDecoder('utf-8');
  await Promise.all(uris.map(async uri => {
    try {
      const open = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri.toString());
      if (open) { out.push({ path: uri.fsPath, text: open.getText() }); return; }
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_FILE_BYTES) return;
      out.push({ path: uri.fsPath, text: decoder.decode(await vscode.workspace.fs.readFile(uri)) });
    } catch { /* archivo ilegible: se omite */ }
  }));
  // runtimeconfig.json vive en bin/ u obj/: se busca aparte, respetando el resto de exclusiones.
  const rcExclude = exclude.filter(g => !/(^|\/)(bin|obj)(\/|$)/.test(g.replace(/^\*\*\//, '')));
  const rcUris = await vscode.workspace.findFiles(RUNTIMECONFIG_GLOB, rcExclude.length ? `{${rcExclude.join(',')}}` : undefined, 500);
  await Promise.all(rcUris.filter(u => !/\.runtimeconfig\.dev\.json$/i.test(u.fsPath)).map(async uri => {
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_FILE_BYTES) return;
      out.push({ path: uri.fsPath, text: decoder.decode(await vscode.workspace.fs.readFile(uri)) });
    } catch { /* ilegible */ }
  }));
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** Carpetas del workspace (multiraíz): cada archivo se resuelve contra la suya. */
const rootFolders = (): RootFolder[] =>
  (vscode.workspace.workspaceFolders ?? []).map(f => ({ name: f.name, path: f.uri.fsPath }));

/** Guarda en cada ubicación el URI de su carpeta de workspace. */
function annotateWorkspaces(stack: ProjectStack) {
  const tag = (loc: { file: string; workspace?: string }) => {
    loc.workspace = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(loc.file))?.uri.toString();
  };
  for (const d of stack.dependencies) tag(d.location);
  for (const r of stack.runtimes) tag(r.location);
  for (const k of stack.sdks ?? []) tag(k.location);
}

// ---------------- Red, auth y caché ----------------

const httpFetch: FetchLike = (url, init) => (fetchImpl ?? ((u, i) => fetch(u, i as RequestInit) as any))(url, init);

async function githubToken(): Promise<string | undefined> {
  if (!cfg().get<boolean>('github.useVSCodeAuth', true)) return undefined;
  try {
    const s = await vscode.authentication.getSession('github', [], { silent: true });
    return s?.accessToken;
  } catch { return undefined; }
}

async function signIn() {
  try {
    await vscode.authentication.getSession('github', [], { createIfNone: true });
    rateLimitWarned = false;
    vscode.window.showInformationMessage('VulnSync: sesión de GitHub conectada.');
    requestScan({ interactive: true });
  } catch (e: any) {
    vscode.window.showErrorMessage(`VulnSync: no se pudo iniciar sesión: ${e?.message ?? e}`);
  }
}

function cacheUri() { return vscode.Uri.joinPath(ctx.globalStorageUri, 'msrc-cache.json'); }

async function loadMsrcCache(): Promise<MsrcCache> {
  try {
    const raw = await vscode.workspace.fs.readFile(cacheUri());
    return JSON.parse(new TextDecoder().decode(raw));
  } catch { return { docs: {} }; }
}

async function saveMsrcCache(c: MsrcCache) {
  await vscode.workspace.fs.createDirectory(ctx.globalStorageUri);
  await vscode.workspace.fs.writeFile(cacheUri(), new TextEncoder().encode(JSON.stringify(c)));
}

async function clearCache() {
  try { await vscode.workspace.fs.delete(cacheUri()); } catch { /* no existía */ }
  await ctx.workspaceState.update('lastScan', undefined);
  // Nada del resultado anterior debe quedar visible ni reutilizable.
  lastStack = undefined;
  lastResult = undefined;
  diagnostics.clear();
  findingsTree.clear();
  stackTree.clear();
  statusBar.backgroundColor = undefined;
  setStatus('$(shield) VulnSync', 'Caché borrada. Ejecuta un escaneo para ver resultados.');
  // No se espera la respuesta: el borrado ya terminó y el aviso puede quedar sin atender.
  void vscode.window.showInformationMessage('VulnSync: caché borrada.', 'Borrar y volver a escanear')
    .then(pick => pick && requestScan({ interactive: true, forceMsrc: true }));
}

function listInstalledRuntimes(): Promise<ReturnType<typeof parseDotnetListRuntimes> | undefined> {
  return new Promise(resolve => {
    execFile('dotnet', ['--list-runtimes'], { timeout: 8000, windowsHide: true }, (err, stdout) => {
      if (err) { output.appendLine('dotnet no está disponible en el PATH; los hallazgos de runtime quedan "por confirmar".'); resolve(undefined); return; }
      resolve(parseDotnetListRuntimes(stdout));
    });
  });
}

// ---------------- Comandos ----------------

async function showReport() {
  if (!lastStack || !lastResult) { await requestScan({ interactive: true }); }
  if (!lastStack || !lastResult) return;
  const doc = await vscode.workspace.openTextDocument({ language: 'markdown', content: renderMarkdownReport(lastStack, lastResult, rootFolders()) });
  await vscode.window.showTextDocument(doc, { preview: false });
  await vscode.commands.executeCommand('markdown.showPreview', doc.uri);
}

async function ignoreFinding(arg: any) {
  const f: Finding | undefined = arg?.f ?? arg;
  if (!f) return;
  const list = cfg().get<string[]>('ignoredAdvisories', []);
  if (!list.includes(f.id)) {
    const target = vscode.workspace.workspaceFolders ? vscode.ConfigurationTarget.Workspace : vscode.ConfigurationTarget.Global;
    await cfg().update('ignoredAdvisories', [...list, f.id], target);
  }
  vscode.window.showInformationMessage(`VulnSync: ${f.id} ignorado (vulnsync.ignoredAdvisories).`);
}
