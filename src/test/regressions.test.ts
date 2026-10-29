// Pruebas de regresión de los reportes VS-001 … VS-013 (auditoría 0.1.0).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectStack, ProjectFile } from '../core/detect';
import { scanStack, renderMarkdownReport } from '../core/scan';
import { GhsaAdvisory, matchGithubAdvisories, queryGithubAdvisories } from '../core/sources/github';
import { describeMsrcStatus, matchMsrc, msrcNeedsSync, resolveInstalledRuntime, syncMsrc, MsrcCache } from '../core/sources/msrc';
import { declaredIntersectsVulnerable } from '../core/version';
import { planUpgrade } from '../core/fix';
import { codeSpan, escapeMd, relativeToRoots, safeUrl } from '../core/text';
import { Dependency } from '../core/types';

const R = '/repo';
const ok = (body: any, headers: Record<string, string> = {}) => ({
  ok: true, status: 200, headers: { get: (h: string) => headers[h.toLowerCase()] ?? null },
  json: async () => body, text: async () => '',
});
const fail = (status: number, headers: Record<string, string> = {}) => ({
  ok: false, status, headers: { get: (h: string) => headers[h.toLowerCase()] ?? null },
  json: async () => ({}), text: async () => 'boom',
});

const adv = (name: string, range: string, eco = 'npm', id = 'GHSA-aaaa-bbbb-cccc'): GhsaAdvisory => ({
  ghsa_id: id, cve_id: null, html_url: `https://github.com/advisories/${id}`, summary: `vuln in ${name}`,
  severity: 'high', withdrawn_at: null,
  vulnerabilities: [{ package: { ecosystem: eco, name }, vulnerable_version_range: range, first_patched_version: '9.9.9' }],
});

const npmPkg = (deps: Record<string, string>): ProjectFile =>
  ({ path: `${R}/package.json`, text: JSON.stringify({ dependencies: deps }, null, 2) });

// ---------- VS-001 ----------
test('VS-001: GitHub caído → escaneo incompleto y 0 dependencias verificadas', async () => {
  const stack = detectStack([npmPkg({ lodash: '4.17.0' })], { ecosystems: ['npm'], includeTransitive: true });
  const r = await scanStack(stack, { fetch: async () => fail(500), minimumSeverity: 'low', ignored: [] });
  assert.equal(r.complete, false);
  assert.equal(r.checkedDependencies, 0);
  assert.equal(r.failedDependencies, 1);
  assert.equal(r.sources.find(s => s.source === 'github')!.state, 'failed');
  const md = renderMarkdownReport(stack, r, R);
  assert.ok(md.includes('ESCANEO INCOMPLETO'));
  assert.ok(!md.includes('✅'));
});

test('VS-001: límite de API (429/403) y respuesta inválida no se muestran como limpios', async () => {
  const stack = detectStack([npmPkg({ lodash: '4.17.0' })], { ecosystems: ['npm'], includeTransitive: true });
  for (const f of [async () => fail(429), async () => fail(403, { 'x-ratelimit-remaining': '0' }), async () => ok({ not: 'a list' })]) {
    const r = await scanStack(stack, { fetch: f as any, minimumSeverity: 'low', ignored: [] });
    assert.equal(r.complete, false);
    assert.equal(r.checkedDependencies, 0);
  }
});

test('VS-001: lote fallido → fuente parcial; solo cuentan los lotes correctos', async () => {
  const files: ProjectFile[] = [
    npmPkg({ lodash: '4.17.0' }),
    { path: `${R}/app/app.csproj`, text: '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[12.0.3]" /></ItemGroup></Project>' },
  ];
  const stack = detectStack(files, { ecosystems: ['npm', 'nuget'], includeTransitive: true });
  const r = await scanStack(stack, {
    fetch: async (url: string) => (url.includes('ecosystem=npm') ? ok([]) : fail(500)) as any,
    minimumSeverity: 'low', ignored: [],
  });
  assert.equal(r.sources.find(s => s.source === 'github')!.state, 'partial');
  assert.equal(r.checkedDependencies, 1);
  assert.equal(r.failedDependencies, 1);
  assert.equal(r.complete, false);
});

test('VS-001: GitHub ok y sin runtimes → completo', async () => {
  const stack = detectStack([npmPkg({ lodash: '4.17.0' })], { ecosystems: ['npm'], includeTransitive: true });
  const r = await scanStack(stack, { fetch: async () => ok([]) as any, minimumSeverity: 'low', ignored: [] });
  assert.equal(r.complete, true);
  assert.equal(r.checkedDependencies, 1);
  assert.ok(renderMarkdownReport(stack, r, R).includes('✅'));
});

test('VS-001: MSRC sin caché útil o con sincronización fallida no es completo', async () => {
  const csproj: ProjectFile = { path: `${R}/a.csproj`, text: '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>' };
  const stack = detectStack([csproj], { ecosystems: ['nuget'], includeTransitive: true });
  const base = { fetch: async () => ok([]) as any, minimumSeverity: 'low' as const, ignored: [] };
  const none = await scanStack(stack, { ...base, msrcCache: { docs: {} }, msrcSyncError: 'sin red' });
  assert.equal(none.sources.find(s => s.source === 'msrc')!.state, 'failed');
  assert.equal(none.complete, false);
  const cache: MsrcCache = { syncedAt: '2026-10-01T00:00:00Z', docs: { '2026-Sep': { currentReleaseDate: 'x', entries: [] } } };
  const cached = await scanStack(stack, { ...base, msrcCache: cache, msrcSyncError: 'sin red', now: () => Date.parse('2026-10-05T00:00:00Z') });
  const st = cached.sources.find(s => s.source === 'msrc')!;
  assert.equal(st.state, 'cached');
  assert.match(st.detail!, /2026-10-01/);
  assert.equal(cached.complete, false);
});

// ---------- VS-002 ----------
test('VS-002: intersección entre rango declarado y vulnerable', () => {
  assert.equal(declaredIntersectsVulnerable('>=1,<3', 'pip', '>= 2.0, < 2.5'), true);
  assert.equal(declaredIntersectsVulnerable('>=1,<2', 'pip', '>= 2.0, < 2.5'), false);
  assert.equal(declaredIntersectsVulnerable('^1.2.3', 'npm', '< 1.2.0'), false);
  assert.equal(declaredIntersectsVulnerable('^1.2.3', 'npm', '>= 1.5.0, < 1.6.0'), true);
  assert.equal(declaredIntersectsVulnerable('~1.2.3', 'npm', '>= 1.3.0'), false);
  assert.equal(declaredIntersectsVulnerable('1.x || >=3', 'npm', '= 3.1.0'), true);
  assert.equal(declaredIntersectsVulnerable('[1.0,2.0)', 'nuget', '>= 2.0'), false);
  assert.equal(declaredIntersectsVulnerable('12.0.3', 'nuget', '< 13.0.1'), true);
  assert.equal(declaredIntersectsVulnerable('~=2.2', 'pip', '< 2.0'), false);
});

test('VS-002: sin lockfile se consulta por nombre y se marca como "por confirmar"', async () => {
  const stack = detectStack([{ path: `${R}/req/requirements.txt`, text: 'foo>=1,<3\n' }], { ecosystems: ['pip'], includeTransitive: true });
  const urls: string[] = [];
  const a = adv('foo', '>= 2.0, < 2.5', 'pip');
  const r = await scanStack(stack, {
    fetch: async (url: string) => { urls.push(url); return ok([a]) as any; }, minimumSeverity: 'low', ignored: [],
  });
  assert.ok(decodeURIComponent(urls[0]).includes('affects=foo') && !decodeURIComponent(urls[0]).includes('foo@'));
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].uncertain, true);
  assert.equal(r.findings[0].declaredRange, '>=1,<3');
});

test('VS-002: NuGet sin lockfile no es versión exacta; rango fuera del vulnerable no genera hallazgo', () => {
  const deps = detectStack([{ path: `${R}/a.csproj`, text: '<Project><ItemGroup><PackageReference Include="X" Version="1.0.0" /></ItemGroup></Project>' }],
    { ecosystems: ['nuget'], includeTransitive: true }).dependencies;
  assert.equal(deps[0].approximate, true);
  assert.equal(matchGithubAdvisories(deps, [adv('X', '< 0.5', 'nuget')]).length, 0);
  assert.equal(matchGithubAdvisories(deps, [adv('X', '>= 2.0', 'nuget')]).length, 1);   // ">=1.0.0" admite 2.x
});

// ---------- VS-003 ----------
const lockMono = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'root', workspaces: ['apps/*'] },
    'apps/a': { name: 'a', dependencies: { x: '^2.0.0' } },
    'apps/b': { name: 'b', dependencies: { x: '^1.0.0', y: '^1.0.0' } },
    'node_modules/x': { version: '1.0.0' },
    'apps/a/node_modules/x': { version: '2.0.0', dependencies: { z: '^1.0.0' } },
    'node_modules/y': { version: '1.1.0', dependencies: { z: '^2.0.0' } },
    'node_modules/z': { version: '2.5.0' },
    'apps/a/node_modules/x/node_modules/z': { version: '1.0.1' },
  },
}, null, 2);

test('VS-003: cada workspace recibe la versión de su ruta y sus transitivas', () => {
  const files: ProjectFile[] = [
    { path: `${R}/package-lock.json`, text: lockMono },
    { path: `${R}/apps/a/package.json`, text: JSON.stringify({ dependencies: { x: '^2.0.0' } }, null, 2) },
    { path: `${R}/apps/b/package.json`, text: JSON.stringify({ dependencies: { x: '^1.0.0', y: '^1.0.0' } }, null, 2) },
  ];
  const s = detectStack(files, { ecosystems: ['npm'], includeTransitive: true });
  const at = (ws: string, n: string) => s.dependencies.find(d => d.location.file.includes(`/${ws}/package.json`) && d.name === n);
  assert.equal(at('a', 'x')!.version, '2.0.0');
  assert.equal(at('b', 'x')!.version, '1.0.0');
  const tr = s.dependencies.filter(d => !d.direct).map(d => `${d.name}@${d.version}`).sort();
  assert.deepEqual(tr, ['z@1.0.1', 'z@2.5.0']);   // las dos versiones de z, cada una por su camino
});

// ---------- VS-004 ----------
test('VS-004: una paginación hacia otro dominio nunca recibe el token', async () => {
  const calls: { url: string; auth?: string }[] = [];
  const fake = async (url: string, init?: any) => {
    calls.push({ url, auth: init?.headers?.Authorization });
    return ok([], { link: '<https://attacker.invalid/steal>; rel="next"' }) as any;
  };
  const deps: Dependency[] = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.0', direct: true, location: { file: 'f', line: 0, startCol: 0, endCol: 1 } }];
  const res = await queryGithubAdvisories(deps, { fetch: fake, token: 'secret-token' });
  assert.equal(calls.length, 1);
  assert.ok(calls.every(c => new URL(c.url).hostname === 'api.github.com'));
  assert.equal(res.batches[0].ok, false);
  assert.ok(res.checked.size === 0);
});

test('VS-004: se rechazan variantes de origen y se envía la versión de API', async () => {
  for (const bad of ['http://api.github.com/advisories?after=1', 'https://api.github.com.evil.com/advisories?after=1',
    'https://user:pw@api.github.com/advisories?after=1', 'https://api.github.com:8443/advisories?after=1', 'https://api.github.com/other?after=1']) {
    const calls: string[] = [];
    const deps: Dependency[] = [{ ecosystem: 'npm', name: 'a', version: '1.0.0', direct: true, location: { file: 'f', line: 0, startCol: 0, endCol: 1 } }];
    await queryGithubAdvisories(deps, { fetch: async (u: string) => { calls.push(u); return ok([], { link: `<${bad}>; rel="next"` }) as any; }, token: 't' });
    assert.equal(calls.length, 1, bad);
  }
  let headers: any;
  const deps: Dependency[] = [{ ecosystem: 'npm', name: 'a', version: '1.0.0', direct: true, location: { file: 'f', line: 0, startCol: 0, endCol: 1 } }];
  await queryGithubAdvisories(deps, { fetch: async (_u, init) => { headers = init?.headers; return ok([]) as any; } });
  assert.equal(headers['X-GitHub-Api-Version'], '2022-11-28');
});

// ---------- VS-005 ----------
const net = (extra: string, sdk = 'Microsoft.NET.Sdk.Web') =>
  `<Project Sdk="${sdk}"><PropertyGroup><TargetFramework>net8.0</TargetFramework>${extra}</PropertyGroup></Project>`;
const cve = { cve: 'CVE-2026-1', title: 't', severity: 'high' as const, product: '.NET' as const, band: '8.0', productName: '.NET 8.0', fixedBuild: '8.0.11', docId: 'd' };

test('VS-005: global.json es SDK (informativo), no un runtime', () => {
  const s = detectStack([{ path: `${R}/global.json`, text: '{"sdk":{"version":"8.0.100"}}' }], { ecosystems: ['nuget'], includeTransitive: true });
  assert.equal(s.runtimes.length, 0);
  assert.equal(s.sdks![0].version, '8.0.100');
});

test('VS-005: aplicación autocontenida no usa los runtimes globales', () => {
  const s = detectStack([{ path: `${R}/a/a.csproj`, text: net('<SelfContained>true</SelfContained><RuntimeFrameworkVersion>8.0.5</RuntimeFrameworkVersion>') }],
    { ecosystems: ['nuget'], includeTransitive: true });
  const f = matchMsrc(s.runtimes, [cve], [{ product: '.NET', version: '8.0.20' }]);
  assert.equal(f.length, 1);
  assert.equal(f[0].installedVersion, '8.0.5');
  assert.equal(f[0].uncertain, false);
  assert.equal(f[0].app, 'a.csproj');
  assert.match(f[0].evidence!, /autocontenida/);
});

test('VS-005: autocontenida sin versión fijada → por confirmar', () => {
  const s = detectStack([{ path: `${R}/a/a.csproj`, text: net('<SelfContained>true</SelfContained>') }], { ecosystems: ['nuget'], includeTransitive: true });
  const f = matchMsrc(s.runtimes, [cve], [{ product: '.NET', version: '8.0.20' }]);
  assert.equal(f.length, 1);
  assert.equal(f[0].uncertain, true);
});

test('VS-005: una biblioteca nunca produce un hallazgo confirmado', () => {
  const s = detectStack([{ path: `${R}/lib/lib.csproj`, text: net('', 'Microsoft.NET.Sdk') }], { ecosystems: ['nuget'], includeTransitive: true });
  const f = matchMsrc(s.runtimes, [cve], [{ product: '.NET', version: '8.0.3' }]);
  assert.equal(f.length, 1);
  assert.equal(f[0].uncertain, true);
});

test('VS-005: runtimeconfig.json aporta versión, roll-forward y autocontenido', () => {
  const files: ProjectFile[] = [
    { path: `${R}/a/a.csproj`, text: net('') },
    { path: `${R}/a/bin/Release/net8.0/a.runtimeconfig.json`, text: JSON.stringify({ runtimeOptions: { tfm: 'net8.0', includedFrameworks: [{ name: 'Microsoft.NETCore.App', version: '8.0.7' }] } }) },
  ];
  const s = detectStack(files, { ecosystems: ['nuget'], includeTransitive: true });
  const t = s.runtimes.find(r => r.product === '.NET')!;
  assert.equal(t.version, '8.0.7');
  assert.equal(t.selfContained, true);
  assert.match(t.evidence, /runtimeconfig/);
});

test('VS-005: política de roll-forward', () => {
  const inst = ['8.0.10', '8.0.11', '9.0.2', '9.0.4', '10.0.0-rc.1'];
  assert.equal(resolveInstalledRuntime('8.0.0', undefined, inst), '8.0.11');
  assert.equal(resolveInstalledRuntime('8.0.0', 'Disable', inst), undefined);
  assert.equal(resolveInstalledRuntime('8.0.10', 'Disable', inst), '8.0.10');
  assert.equal(resolveInstalledRuntime('8.1.0', 'Minor', inst), undefined);
  assert.equal(resolveInstalledRuntime('8.1.0', 'Major', inst), '9.0.4');
  assert.equal(resolveInstalledRuntime('8.0.0', 'LatestMajor', inst), '9.0.4');
});

// ---------- VS-006 ----------
test('VS-006: las correcciones automáticas nunca amplían el rango', () => {
  const edit = (eco: any, cur: string, fix: string) => { const p = planUpgrade(eco, cur, fix); return p.kind === 'edit' ? p.text : p.kind; };
  assert.equal(edit('pip', '>=2,<3', '2.5.0'), 'suggest');
  assert.equal(edit('pip', '>=2.0', '2.5.0'), '>=2.5.0');
  assert.equal(edit('pip', '==2.0', '2.5.0'), '==2.5.0');
  assert.equal(edit('npm', '>=1 <2', '1.8.0'), 'suggest');
  assert.equal(edit('npm', '^1.2.3', '1.8.0'), '^1.8.0');
  assert.equal(edit('npm', '^1.2.3', '2.0.1'), 'suggest');      // saldría del rango: no se toca
  assert.equal(edit('npm', '~1.2.3', '1.3.0'), 'suggest');
  assert.equal(edit('npm', '1.2.3', '1.2.9'), '1.2.9');
  assert.equal(edit('npm', '^1 || ^2', '2.1.0'), 'suggest');
  assert.equal(edit('nuget', '[1.0,2.0)', '1.5.0'), 'suggest');
  assert.equal(edit('nuget', '[1.0.0]', '1.0.5'), '[1.0.5]');
  assert.equal(edit('nuget', '1.0.0', '1.0.5'), '1.0.5');
  assert.equal(edit('pip', '~=2.2', '2.9'), '~=2.9');
  assert.equal(edit('pip', '~=2.2', '3.0'), 'suggest');
  assert.equal(edit('npm', '^1.2.3', '1.0.0'), 'none');
});

// ---------- VS-007 ----------
test('VS-007: Pipenv — Pipfile + Pipfile.lock, directas/transitivas e includeTransitive', () => {
  const files: ProjectFile[] = [
    { path: `${R}/p/Pipfile`, text: '[packages]\nrequests = "*"\nflask = {version = ">=2.0"}\n\n[dev-packages]\npytest = "==7.0.0"\n' },
    { path: `${R}/p/Pipfile.lock`, text: JSON.stringify({
      default: { requests: { version: '==2.25.0' }, flask: { version: '==2.1.0' }, werkzeug: { version: '==2.0.0' } },
      develop: { pytest: { version: '==7.0.0' } } }, null, 2) },
  ];
  const on = detectStack(files, { ecosystems: ['pip'], includeTransitive: true });
  const off = detectStack(files, { ecosystems: ['pip'], includeTransitive: false });
  const get = (s: any, n: string) => s.dependencies.find((d: Dependency) => d.name === n);
  assert.equal(get(on, 'requests').version, '2.25.0');
  assert.equal(get(on, 'requests').direct, true);
  assert.equal(get(on, 'werkzeug').direct, false);
  assert.equal(get(on, 'pytest').direct, true);
  assert.equal(off.dependencies.length, 3);
  assert.ok(!get(off, 'werkzeug'));
  // Solo el lockfile: no se puede distinguir, no debe quedar vacío.
  const lockOnly = detectStack([files[1]], { ecosystems: ['pip'], includeTransitive: false });
  assert.equal(lockOnly.dependencies.length, 4);
});

// ---------- VS-008 ----------
test('VS-008: un documento MSRC fallido deja la caché parcial, con reintento y backoff', async () => {
  const updates = { value: [
    { ID: '2026-Oct', DocumentTitle: 'o', InitialReleaseDate: '2026-10-13T00:00:00Z', CurrentReleaseDate: 'c1', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct' },
    { ID: '2026-Sep', DocumentTitle: 's', InitialReleaseDate: '2026-09-08T00:00:00Z', CurrentReleaseDate: 'c2', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep' },
  ] };
  let failSep = true;
  const fake = async (url: string) => {
    if (url.endsWith('/updates')) return ok(updates) as any;
    if (url.endsWith('2026-Sep') && failSep) return fail(500) as any;
    return ok({}) as any;
  };
  let now = Date.parse('2026-10-20T00:00:00Z');
  const first = await syncMsrc(fake, { docs: {} }, 12, { now: () => now });
  assert.equal(first.failed.length, 1);
  assert.equal(first.cache.syncedAt, undefined);              // nunca se declara sincronización completa
  assert.equal(describeMsrcStatus(first.cache, undefined, now).state, 'partial');
  assert.match(describeMsrcStatus(first.cache, undefined, now).detail!, /2026-Sep/);
  assert.equal(msrcNeedsSync(first.cache, now, 12 * 3600_000), true);

  const second = await syncMsrc(fake, first.cache, 12, { now: () => now + 1000 });
  assert.equal(second.failed[0].attempts, 2);
  assert.ok(Date.parse(second.failed[0].nextRetryAt) - Date.parse(first.failed[0].nextRetryAt) > 4 * 60_000);

  failSep = false;
  now += 3600_000;
  const third = await syncMsrc(fake, second.cache, 12, { now: () => now });
  assert.equal(third.failed.length, 0);
  assert.ok(third.cache.syncedAt);
  assert.equal(describeMsrcStatus(third.cache, undefined, now).state, 'complete');
});

// ---------- VS-011 ----------
test('VS-011: rutas relativas por carpeta de workspace, nunca absolutas', () => {
  const roots = [{ name: 'api', path: 'C:\\w\\api' }, { name: 'web', path: 'C:\\w\\web' }];
  assert.equal(relativeToRoots('C:\\w\\web\\package.json', roots), 'web/package.json');
  assert.equal(relativeToRoots('c:\\w\\api\\src\\a.csproj', roots), 'api/src/a.csproj');
  assert.equal(relativeToRoots('C:\\other\\secret\\x.json', roots), '…/x.json');
  assert.equal(relativeToRoots('/repo/web/package.json', [{ name: 'repo', path: '/repo' }]), 'web/package.json');
});

// ---------- VS-013 ----------
test('VS-013: el contenido externo se escapa y no rompe las tablas', async () => {
  assert.equal(escapeMd('a|b\n[x](javascript:alert(1)) `c`'), 'a\\|b \\[x\\]\\(javascript:alert\\(1\\)\\) \\`c\\`');
  assert.equal(codeSpan('a`b'), '``a`b``');
  assert.equal(safeUrl('javascript:alert(1)'), undefined);
  assert.equal(safeUrl('https://example.com/a b'), 'https://example.com/a%20b');

  const evil = adv('ev|il', '< 2.0.0');
  evil.summary = 'x |\n| injected | row';
  evil.html_url = 'javascript:alert(1)';
  const stack = detectStack([npmPkg({ 'ev|il': '1.0.0' })], { ecosystems: ['npm'], includeTransitive: true });
  const r = await scanStack(stack, { fetch: async () => ok([evil]) as any, minimumSeverity: 'low', ignored: [] });
  const md = renderMarkdownReport(stack, r, R);
  assert.ok(!md.includes('javascript:alert(1))'));
  const rows = md.split('\n').filter(l => l.startsWith('| high'));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].replace(/\\\|/g, '').split('|').length, 9);   // 7 columnas
});
