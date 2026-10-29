import { Dependency, RuntimeTarget, SdkInfo } from '../types';
import { locate, locateNeedle } from '../text';
import { exactPin, lowerBoundOf } from '../version';

export interface CsprojResult {
  dependencies: Dependency[];
  /** Nombre de paquete → índice en dependencies, para enlazar versiones centrales. */
  centrallyManaged: string[];
  runtimes: RuntimeTarget[];
}

/**
 * *.csproj / *.fsproj / *.vbproj / Directory.Build.props / Directory.Packages.props.
 * Soporta:
 *   <PackageReference Include="X" Version="1.2.3" />
 *   <PackageReference Include="X"><Version>1.2.3</Version></PackageReference>
 *   <PackageVersion Include="X" Version="1.2.3" />   (Central Package Management)
 *   <TargetFramework(s)>net8.0;net9.0</TargetFramework(s)>
 *   <RuntimeFrameworkVersion>8.0.10</RuntimeFrameworkVersion>
 *   <Project Sdk="Microsoft.NET.Sdk.Web">  → implica ASP.NET Core
 */
export function parseMsBuildProject(file: string, text: string): CsprojResult {
  const deps: Dependency[] = [];
  const central: string[] = [];
  const elRe = /<(PackageReference|PackageVersion)\b([^>]*?)(\/>|>([\s\S]*?)<\/\1>)/g;
  let m: RegExpExecArray | null;
  while ((m = elRe.exec(text))) {
    const attrs = m[2];
    const name = attr(attrs, 'Include') ?? attr(attrs, 'Update');
    if (!name) continue;
    let version = attr(attrs, 'Version') ?? attr(attrs, 'VersionOverride');
    let versionOffset = -1;
    if (version !== undefined) {
      const local = m[0].search(new RegExp(`Version(Override)?\\s*=\\s*["']${escapeRe(version)}`));
      versionOffset = m.index + m[0].indexOf(version, Math.max(local, 0));
    } else if (m[4]) {
      const inner = /<Version>\s*([^<\s]+)\s*<\/Version>/.exec(m[4]);
      if (inner) {
        version = inner[1];
        versionOffset = m.index + m[0].indexOf(inner[1], m[0].indexOf('<Version>'));
      }
    }
    if (version === undefined) {
      // Versión gestionada centralmente en Directory.Packages.props
      central.push(name);
      continue;
    }
    if (version.includes('$(')) continue; // propiedades MSBuild: no se resuelven
    const loc = versionOffset >= 0
      ? locate(text, file, versionOffset, version.length)
      : locate(text, file, m.index, m[0].length);
    const pin = exactPin(version, 'nuget');
    deps.push({
      ecosystem: 'nuget', name, declared: version, direct: true, location: loc,
      version: pin ?? lowerBoundOf(version, 'nuget'),
      approximate: !pin,
    });
  }

  const runtimes: RuntimeTarget[] = [];
  const isWeb = /<Project\s+Sdk\s*=\s*["']Microsoft\.NET\.Sdk\.(Web|Razor|BlazorWebAssembly)/i.test(text)
    || /<FrameworkReference\s+Include\s*=\s*["']Microsoft\.AspNetCore\.App/i.test(text);
  const isExe = isWeb
    || /<OutputType>\s*(Exe|WinExe)\s*</i.test(text)
    || /<Project\s+Sdk\s*=\s*["']Microsoft\.NET\.Sdk\.Worker/i.test(text);
  const selfContained = /<SelfContained>\s*true\s*</i.test(text);
  const rollForward = /<RollForward>\s*([^<\s]+)\s*</i.exec(text)?.[1];
  const rfv = /<RuntimeFrameworkVersion>\s*([^<\s]+)\s*</.exec(text)?.[1];
  const app = baseName(file);
  const tfRe = /<TargetFrameworks?>\s*([^<]+?)\s*<\/TargetFrameworks?>/g;
  while ((m = tfRe.exec(text))) {
    for (const tfm of m[1].split(';').map(s => s.trim()).filter(Boolean)) {
      // net5.0+ (no netstandard, no net4x de .NET Framework)
      const t = /^net(\d+)\.(\d+)/.exec(tfm);
      if (!t || parseInt(t[1], 10) < 5) {
        const core = /^netcoreapp(\d+)\.(\d+)/.exec(tfm);
        if (!core) continue;
        addRuntime(`${core[1]}.${core[2]}`);
        continue;
      }
      addRuntime(`${t[1]}.${t[2]}`);
    }
  }
  function addRuntime(band: string) {
    const loc = locateNeedle(text, file, band, text.search(/<TargetFrameworks?>/));
    const version = rfv && rfv.startsWith(band + '.') ? rfv : undefined;
    const base = {
      band, version, app, appKind: (isExe ? 'app' : 'library') as 'app' | 'library',
      selfContained, rollForward,
      evidence: version ? `RuntimeFrameworkVersion en ${app}` : `TargetFramework en ${app}`,
      source: `TargetFramework en ${app}`, location: loc,
    };
    runtimes.push({ product: '.NET', ...base });
    if (isWeb) runtimes.push({ product: 'ASP.NET Core', ...base, source: `SDK Web en ${app}` });
  }
  return { dependencies: deps, centrallyManaged: central, runtimes };
}

/**
 * packages.lock.json (RestorePackagesWithLockFile). Formato:
 * { "dependencies": { "net8.0": { "Pkg": { "type": "Direct|Transitive|CentralTransitive", "resolved": "1.2.3" } } } }
 */
export function parseNugetLock(file: string, text: string): Dependency[] {
  let json: any;
  try { json = JSON.parse(text); } catch { return []; }
  const out: Dependency[] = [];
  const seen = new Set<string>();
  for (const tfmDeps of Object.values<any>(json?.dependencies ?? {})) {
    for (const [name, info] of Object.entries<any>(tfmDeps ?? {})) {
      const version = info?.resolved;
      if (typeof version !== 'string' || info?.type === 'Project') continue;
      const id = `${name.toLowerCase()}@${version}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        ecosystem: 'nuget', name, version, direct: info.type === 'Direct',
        location: locateNeedle(text, file, `"${name}"`),
      });
    }
  }
  return out;
}

/** global.json → SDK fijado. Es evidencia auxiliar, NO un runtime. */
export function parseGlobalJson(file: string, text: string): SdkInfo[] {
  let json: any;
  try { json = JSON.parse(text); } catch { return []; }
  const sdk: string | undefined = json?.sdk?.version;
  if (!sdk) return [];
  return [{ version: sdk, source: 'global.json', location: locateNeedle(text, file, sdk) }];
}

export interface RuntimeConfig {
  /** Nombre del ensamblado (de `X.runtimeconfig.json`). */
  assembly: string;
  tfm?: string;
  frameworkVersion?: string;
  rollForward?: string;
  selfContained: boolean;
  /** Versión incluida cuando la aplicación es autocontenida. */
  includedVersion?: string;
}

/** `*.runtimeconfig.json` generado en la compilación. */
export function parseRuntimeConfig(file: string, text: string): RuntimeConfig | undefined {
  let json: any;
  try { json = JSON.parse(text); } catch { return undefined; }
  const o = json?.runtimeOptions;
  if (!o || typeof o !== 'object') return undefined;
  const assembly = baseName(file).replace(/\.runtimeconfig(\.dev)?\.json$/i, '');
  const fw = (o.framework ?? (Array.isArray(o.frameworks) ? o.frameworks.find((f: any) => /NETCore\.App|AspNetCore\.App/.test(f?.name)) : undefined));
  const included = Array.isArray(o.includedFrameworks)
    ? o.includedFrameworks.find((f: any) => f?.name === 'Microsoft.NETCore.App') : undefined;
  return {
    assembly, tfm: o.tfm,
    frameworkVersion: typeof fw?.version === 'string' ? fw.version : undefined,
    rollForward: typeof o.rollForward === 'string' ? o.rollForward : (typeof fw?.rollForward === 'string' ? fw.rollForward : undefined),
    selfContained: !!included,
    includedVersion: typeof included?.version === 'string' ? included.version : undefined,
  };
}

function attr(attrs: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i').exec(attrs);
  return m?.[1];
}
function escapeRe(s: string) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function baseName(p: string) { return p.split(/[\\/]/).pop() ?? p; }
