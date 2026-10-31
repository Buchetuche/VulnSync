import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, satisfiesGhsaRange, lowerBoundOf, exactPin } from '../core/version';
import { detectStack, ProjectFile } from '../core/detect';
import { matchGithubAdvisories, queryGithubAdvisories, GhsaAdvisory } from '../core/sources/github';
import { reduceCvrf, matchMsrc, parseDotnetListRuntimes, syncMsrc, normalizeMsrcCache, msrcNeedsSync, MSRC_CACHE_SCHEMA } from '../core/sources/msrc';
import { scanStack, renderMarkdownReport } from '../core/scan';

// ---------- versiones ----------
test('compareVersions: semver, NuGet y PEP 440', () => {
  assert.ok(compareVersions('1.2.3', '1.2.10') < 0);
  assert.ok(compareVersions('1.0.0-beta.2', '1.0.0') < 0);
  assert.ok(compareVersions('1.0.0-alpha', '1.0.0-alpha.1') < 0);
  assert.ok(compareVersions('8.0.0-preview.7.23375.6', '8.0.0-rc.1') < 0);
  assert.equal(compareVersions('1.2', '1.2.0.0'), 0);
  assert.ok(compareVersions('2.0.dev1', '2.0a1') < 0);
  assert.ok(compareVersions('2.0rc1', '2.0') < 0);
  assert.ok(compareVersions('2.0.post1', '2.0') > 0);
  assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
});

test('satisfiesGhsaRange', () => {
  assert.ok(satisfiesGhsaRange('4.17.15', '< 4.17.21'));
  assert.ok(!satisfiesGhsaRange('4.17.21', '< 4.17.21'));
  assert.ok(satisfiesGhsaRange('13.0.1', '>= 13.0.0, < 13.0.3'));
  assert.ok(!satisfiesGhsaRange('12.0.3', '>= 13.0.0, < 13.0.3'));
  assert.ok(satisfiesGhsaRange('2.0.0', '= 2.0.0'));
  assert.ok(satisfiesGhsaRange('1.0.2', '<= 1.0.2'));
});

test('lowerBoundOf / exactPin', () => {
  assert.equal(lowerBoundOf('^4.17.1', 'npm'), '4.17.1');
  assert.equal(lowerBoundOf('~1.2.x', 'npm'), '1.2');
  assert.equal(lowerBoundOf('[1.0,2.0)', 'nuget'), '1.0');
  assert.equal(lowerBoundOf('*', 'npm'), undefined);
  assert.equal(exactPin('==2.31.0', 'pip'), '2.31.0');
  assert.equal(exactPin('>=2.31', 'pip'), undefined);
  assert.equal(exactPin('13.0.1', 'nuget'), undefined);   // sin lockfile, "1.2.3" es >=1.2.3
  assert.equal(exactPin('[13.0.1]', 'nuget'), '13.0.1');
  assert.equal(exactPin('4.17.21', 'npm'), '4.17.21');
  assert.equal(exactPin('^4.17.21', 'npm'), undefined);
});

// ---------- detección ----------
const R = '/repo';
const files: ProjectFile[] = [
  { path: `${R}/web/package.json`, text: JSON.stringify({ dependencies: { lodash: '^4.17.0', express: '4.18.2' }, devDependencies: { jest: '^29.0.0' } }, null, 2) },
  { path: `${R}/web/package-lock.json`, text: JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'web' },
      'node_modules/lodash': { version: '4.17.15' },
      'node_modules/express': { version: '4.18.2', dependencies: { qs: '^6.10.0' } },
      'node_modules/jest': { version: '29.7.0', dev: true },
      'node_modules/qs': { version: '6.10.3' },
    },
  }, null, 2) },
  { path: `${R}/api/Api.csproj`, text: `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
    <PackageReference Include="System.Text.Json">
      <Version>8.0.0</Version>
    </PackageReference>
    <PackageReference Include="Serilog" />
  </ItemGroup>
</Project>` },
  { path: `${R}/Directory.Packages.props`, text: `<Project><ItemGroup><PackageVersion Include="Serilog" Version="3.1.1" /></ItemGroup></Project>` },
  { path: `${R}/global.json`, text: JSON.stringify({ sdk: { version: '8.0.100' } }) },
  { path: `${R}/ml/requirements.txt`, text: 'requests==2.25.0\nflask>=2.0,<3  # web\nnumpy\n-r other.txt\n' },
  { path: `${R}/svc/pyproject.toml`, text: '[project]\nname = "svc"\ndependencies = [\n  "urllib3==1.26.4",\n  "pydantic>=2",\n]\n\n[tool.poetry.dependencies]\npython = "^3.11"\njinja2 = "3.1.2"\n' },
  { path: `${R}/svc/poetry.lock`, text: '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n\n[[package]]\nname = "pydantic"\nversion = "2.5.0"\n\n[[package]]\nname = "certifi"\nversion = "2022.12.7"\n' },
];

test('detectStack: npm con lockfile resuelve versiones y transitivas', () => {
  const s = detectStack(files, { ecosystems: ['npm'], includeTransitive: true });
  const lodash = s.dependencies.find(d => d.name === 'lodash' && d.direct)!;
  assert.equal(lodash.version, '4.17.15');
  assert.equal(lodash.approximate, false);
  assert.ok(lodash.location.file.endsWith('package.json'));
  assert.ok(lodash.location.line > 0);
  assert.ok(s.dependencies.some(d => d.name === 'qs' && !d.direct));
});

test('detectStack: .NET con Central Package Management y runtimes', () => {
  const s = detectStack(files, { ecosystems: ['nuget'], includeTransitive: true });
  const names = s.dependencies.map(d => `${d.name}@${d.version}`).sort();
  assert.deepEqual(names, ['Newtonsoft.Json@12.0.3', 'Serilog@3.1.1', 'System.Text.Json@8.0.0']);
  const bands = s.runtimes.map(r => `${r.product} ${r.band}`).sort();
  assert.ok(bands.includes('.NET 8.0'));
  assert.ok(bands.includes('ASP.NET Core 8.0'));
  const nj = s.dependencies.find(d => d.name === 'Newtonsoft.Json')!;
  assert.equal(nj.location.line, 5);
});

test('detectStack: Python requirements + pyproject + poetry.lock', () => {
  const s = detectStack(files, { ecosystems: ['pip'], includeTransitive: true });
  const get = (n: string) => s.dependencies.find(d => d.name === n);
  assert.equal(get('requests')!.version, '2.25.0');
  assert.equal(get('requests')!.approximate, false);
  assert.equal(get('flask')!.version, '2.0');
  assert.equal(get('flask')!.approximate, true);
  assert.equal(get('numpy')!.version, undefined);
  assert.equal(get('pydantic')!.version, '2.5.0');
  assert.equal(get('jinja2')!.version, '3.1.2');
  assert.ok(get('certifi') && !get('certifi')!.direct);
});

// ---------- GitHub Advisory ----------
const lodashAdv: GhsaAdvisory = {
  ghsa_id: 'GHSA-p6mc-m468-83gw', cve_id: 'CVE-2020-8203', html_url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw',
  summary: 'Prototype Pollution in lodash', severity: 'high', withdrawn_at: null,
  cvss_severities: { cvss_v3: { score: 7.4 } },
  vulnerabilities: [{ package: { ecosystem: 'npm', name: 'lodash' }, vulnerable_version_range: '>= 3.7.0, < 4.17.19', first_patched_version: '4.17.19' }],
};
const njAdv: GhsaAdvisory = {
  ghsa_id: 'GHSA-5crp-9r3c-p9vr', cve_id: 'CVE-2024-21907', html_url: 'https://github.com/advisories/GHSA-5crp-9r3c-p9vr',
  summary: 'Improper Handling of Exceptional Conditions in Newtonsoft.Json', severity: 'high', withdrawn_at: null,
  vulnerabilities: [{ package: { ecosystem: 'nuget', name: 'Newtonsoft.Json' }, vulnerable_version_range: '< 13.0.1', first_patched_version: '13.0.1' }],
};

test('matchGithubAdvisories verifica el rango localmente', () => {
  const s = detectStack(files, { ecosystems: ['npm', 'nuget'], includeTransitive: true });
  const f = matchGithubAdvisories(s.dependencies, [lodashAdv, njAdv]);
  assert.deepEqual(f.map(x => `${x.packageName}:${x.id}`).sort(), ['Newtonsoft.Json:GHSA-5crp-9r3c-p9vr', 'lodash:GHSA-p6mc-m468-83gw']);
  assert.equal(f.find(x => x.packageName === 'lodash')!.fixedVersion, '4.17.19');
  assert.equal(f.find(x => x.packageName === 'lodash')!.cvss, 7.4);
});

test('queryGithubAdvisories: lotes por ecosistema, paginación y token', async () => {
  const calls: string[] = [];
  let auth = '';
  const fake = async (url: string, init?: any) => {
    calls.push(url);
    auth = init?.headers?.Authorization ?? '';
    const page2 = url.includes('after=abc');
    const isNpm = url.includes('ecosystem=npm');
    return {
      ok: true, status: 200,
      headers: { get: (h: string) => (h === 'link' && isNpm && !page2 ? '<https://api.github.com/advisories?ecosystem=npm&after=abc>; rel="next"' : null) },
      json: async () => (isNpm ? (page2 ? [] : [lodashAdv]) : [njAdv]),
      text: async () => '',
    };
  };
  const s = detectStack(files, { ecosystems: ['npm', 'nuget'], includeTransitive: false });
  const adv = await queryGithubAdvisories(s.dependencies, { fetch: fake, token: 't0k' });
  assert.equal(adv.advisories.length, 2);
  assert.ok(adv.batches.every(b => b.ok));
  assert.equal(calls.length, 3);
  assert.ok(calls[0].includes('affects='));
  assert.ok(decodeURIComponent(calls.find(c => c.includes('nuget'))!).includes('affects=Newtonsoft.Json'));   // sin lockfile se consulta por nombre
  assert.equal(auth, 'Bearer t0k');
});

// ---------- MSRC ----------
const cvrfDoc = {
  ProductTree: {
    FullProductName: [
      { ProductID: '11655', Value: '.NET 8.0 installed on Windows' },
      { ProductID: '11656', Value: '.NET 8.0 installed on Linux' },
      { ProductID: '11700', Value: 'ASP.NET Core 8.0' },
      { ProductID: '12000', Value: 'Microsoft .NET Framework 4.8' },
      { ProductID: '13000', Value: 'Windows 11 Version 24H2' },
    ],
  },
  Vulnerability: [
    {
      CVE: 'CVE-2026-11111', Title: { Value: '.NET Denial of Service Vulnerability' },
      ProductStatuses: [{ Type: 3, ProductID: ['11655', '11656', '12000'] }],
      Threats: [{ Type: 3, ProductID: ['11655', '11656'], Description: { Value: 'Important' } }],
      CVSSScoreSets: [{ BaseScore: 7.5, ProductID: ['11655'] }],
      Remediations: [
        { Type: 2, ProductID: ['11655', '11656'], FixedBuild: '8.0.11', Description: { Value: 'Release Notes' } },
      ],
    },
    {
      CVE: 'CVE-2026-22222', Title: { Value: 'ASP.NET Core Security Feature Bypass' },
      ProductStatuses: [{ Type: 3, ProductID: ['11700'] }],
      Threats: [{ Type: 3, ProductID: ['11700'], Description: { Value: 'Critical' } }],
      Remediations: [{ Type: 2, ProductID: ['11700'], Description: { Value: '8.0.11' } }],
    },
    {
      CVE: 'CVE-2026-33333', Title: { Value: 'Windows Kernel EoP' },
      ProductStatuses: [{ Type: 3, ProductID: ['13000'] }],
      Remediations: [{ Type: 2, ProductID: ['13000'], Description: { Value: '5059200' } }],
    },
  ],
};

test('reduceCvrf conserva solo .NET / ASP.NET Core y una entrada por banda', () => {
  const e = reduceCvrf(cvrfDoc, '2026-Oct');
  assert.equal(e.length, 2);
  const net = e.find(x => x.cve === 'CVE-2026-11111')!;
  assert.equal(net.product, '.NET');
  assert.equal(net.band, '8.0');
  assert.equal(net.fixedBuild, '8.0.11');
  assert.equal(net.severity, 'high');
  assert.equal(net.cvss, 7.5);
  const asp = e.find(x => x.cve === 'CVE-2026-22222')!;
  assert.equal(asp.product, 'ASP.NET Core');
  assert.equal(asp.severity, 'critical');
  assert.equal(asp.fixedBuild, '8.0.11');
});

test('MSRC separa versiones de runtime y de SDK', () => {
  const doc = {
    ProductTree: { FullProductName: [{ ProductID: '1', Value: '.NET 8.0 installed on Windows' }] },
    Vulnerability: [
      { CVE: 'CVE-SOLO-SDK', ProductStatuses: [{ Type: 3, ProductID: ['1'] }], Remediations: [{ ProductID: ['1'], FixedBuild: '8.0.427' }] },
      { CVE: 'CVE-AMBAS', ProductStatuses: [{ Type: 3, ProductID: ['1'] }],
        Remediations: [{ ProductID: ['1'], FixedBuild: '8.0.427' }, { ProductID: ['1'], FixedBuild: '8.0.32' }] },
    ],
  };
  const e = reduceCvrf(doc, 'x');
  const soloSdk = e.find(x => x.cve === 'CVE-SOLO-SDK')!;
  assert.equal(soloSdk.fixedBuild, undefined);
  assert.equal(soloSdk.sdkFixedBuild, '8.0.427');
  assert.equal(e.find(x => x.cve === 'CVE-AMBAS')!.fixedBuild, '8.0.32');
  const target = {
    product: '.NET' as const, band: '8.0', app: 'a.csproj', appKind: 'app' as const, evidence: 't', source: 't',
    location: { file: 'a.csproj', line: 0, startCol: 0, endCol: 1 },
  };
  const f = matchMsrc([target], e, [{ product: '.NET', version: '8.0.28' }]);
  const sdkF = f.find(x => x.id === 'CVE-SOLO-SDK')!;
  assert.ok(sdkF.uncertain);
  assert.equal(sdkF.fixedVersion, 'SDK 8.0.427');
  const ambas = f.find(x => x.id === 'CVE-AMBAS')!;
  assert.ok(!ambas.uncertain);
  assert.equal(ambas.fixedVersion, '8.0.32');
  assert.ok(!matchMsrc([target], e, [{ product: '.NET', version: '8.0.32' }]).some(x => x.id === 'CVE-AMBAS'));
});

test('la caché de MSRC de otra versión se descarta y fuerza una nueva descarga', () => {
  const old = { syncedAt: '2026-10-29T00:00:00Z', docs: { '2026-Oct': { currentReleaseDate: 'x', entries: [{ cve: 'CVE-1', fixedBuild: '8.0.427' }] } } };
  const n = normalizeMsrcCache(old);
  assert.deepEqual(n.docs, {});
  assert.equal(n.syncedAt, undefined);
  assert.equal(n.schema, MSRC_CACHE_SCHEMA);
  assert.ok(msrcNeedsSync(n, Date.now(), 12 * 3600_000));
  // Basura o ausente: también se reinicia.
  assert.deepEqual(normalizeMsrcCache(null).docs, {});
  assert.deepEqual(normalizeMsrcCache('x').docs, {});
  // Una caché de la versión actual se conserva tal cual.
  const cur = { schema: MSRC_CACHE_SCHEMA, syncedAt: '2026-10-29T00:00:00Z', docs: { a: { currentReleaseDate: 'x', entries: [] } } };
  assert.equal(normalizeMsrcCache(cur), cur);
});

test('matchMsrc usa los runtimes instalados', () => {
  const entries = reduceCvrf(cvrfDoc, '2026-Oct');
  const s = detectStack(files, { ecosystems: ['nuget'], includeTransitive: true });
  const installedOld = parseDotnetListRuntimes(
    'Microsoft.AspNetCore.App 8.0.10 [/usr/share/dotnet/shared/Microsoft.AspNetCore.App]\n' +
    'Microsoft.NETCore.App 8.0.10 [/usr/share/dotnet/shared/Microsoft.NETCore.App]\n');
  const vuln = matchMsrc(s.runtimes, entries, installedOld);
  assert.ok(vuln.some(f => f.id === 'CVE-2026-11111' && !f.uncertain && f.installedVersion === '8.0.10'));
  assert.ok(vuln.some(f => f.id === 'CVE-2026-22222' && !f.uncertain));

  const installedNew = parseDotnetListRuntimes('Microsoft.NETCore.App 8.0.11 [x]\nMicrosoft.AspNetCore.App 8.0.11 [x]\n');
  assert.equal(matchMsrc(s.runtimes, entries, installedNew).length, 0);

  const unknown = matchMsrc(s.runtimes, entries, undefined);
  assert.ok(unknown.length > 0 && unknown.every(f => f.uncertain));
});

test('syncMsrc es incremental', async () => {
  let docFetches = 0;
  const updates = { value: [
    { ID: '2026-Oct', DocumentTitle: 'Oct', InitialReleaseDate: '2026-10-13T07:00:00Z', CurrentReleaseDate: '2026-10-26T01:48:59Z', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct' },
    { ID: '2026-Sep', DocumentTitle: 'Sep', InitialReleaseDate: '2026-09-08T07:00:00Z', CurrentReleaseDate: '2026-09-20T00:00:00Z', CvrfUrl: 'https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep' },
  ] };
  const fake = async (url: string) => {
    if (!url.endsWith('/updates')) docFetches++;
    return { ok: true, status: 200, headers: { get: () => null }, json: async () => (url.endsWith('/updates') ? updates : cvrfDoc), text: async () => '' };
  };
  const first = await syncMsrc(fake, { docs: {} }, 12);
  assert.equal(first.downloaded, 2);
  const second = await syncMsrc(fake, first.cache, 12);
  assert.equal(second.downloaded, 0);
  assert.equal(docFetches, 2);
});

// ---------- escaneo completo ----------
test('scanStack + reporte, con lista de ignorados', async () => {
  const stack = detectStack(files, { ecosystems: ['npm', 'nuget', 'pip'], includeTransitive: true });
  const fake = async (url: string) => ({
    ok: true, status: 200, headers: { get: () => null },
    json: async () => (url.includes('npm') ? [lodashAdv] : url.includes('nuget') ? [njAdv] : []),
    text: async () => '',
  });
  const msrcCache = { docs: { '2026-Oct': { currentReleaseDate: 'x', entries: reduceCvrf(cvrfDoc, '2026-Oct') } } };
  const r = await scanStack(stack, {
    fetch: fake, msrcCache, minimumSeverity: 'low', ignored: ['CVE-2024-21907'],
    installedRuntimes: parseDotnetListRuntimes('Microsoft.NETCore.App 8.0.10 [x]\nMicrosoft.AspNetCore.App 8.0.10 [x]'),
  });
  assert.ok(!r.findings.some(f => f.packageName === 'Newtonsoft.Json'));
  assert.ok(r.findings.some(f => f.packageName === 'lodash'));
  assert.equal(r.findings[0].severity, 'critical');
  const md = renderMarkdownReport(stack, r, R);
  assert.ok(md.includes('CVE-2026-22222'));
  assert.ok(md.includes('web/package.json'));
});
