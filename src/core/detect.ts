// Detección del stack a partir de los archivos del proyecto.
// Recibe contenidos ya leídos para que sea independiente de VS Code.

import { Dependency, Ecosystem, ProjectStack, RuntimeTarget, SdkInfo } from './types';
import { normalizeName } from './text';
import { lockEntryToDependency, NpmLock, parsePackageJson, parsePackageLockTree, resolveWorkspace } from './parsers/npm';
import { parsePnpmLock, parseYarnLock } from './parsers/npmLocks';
import { parseGlobalJson, parseMsBuildProject, parseNugetLock, parseRuntimeConfig } from './parsers/nuget';
import { parsePipfile, parsePipfileLock, parsePyproject, parseRequirements, parseTomlLock } from './parsers/python';

export interface ProjectFile { path: string; text: string; }
export interface DetectOptions { ecosystems: Ecosystem[]; includeTransitive: boolean; }

/** Patrones glob que el host debe leer para llamar a detectStack. */
export const MANIFEST_GLOB =
  '**/{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock,pnpm-lock.yaml,' +
  '*.csproj,*.fsproj,*.vbproj,Directory.Packages.props,Directory.Build.props,packages.lock.json,global.json,' +
  'requirements*.txt,pyproject.toml,poetry.lock,uv.lock,Pipfile,Pipfile.lock}';

/** Salida de compilación de .NET (suele estar excluida del escaneo general). */
export const RUNTIMECONFIG_GLOB = '**/*.runtimeconfig.json';

const dirOf = (p: string) => p.replace(/[\\/][^\\/]*$/, '');
const baseOf = (p: string) => p.split(/[\\/]/).pop()!.toLowerCase();
const slash = (p: string) => p.replace(/\\/g, '/');

/** Ruta del directorio `dir` relativa a `base` ('' si coinciden); undefined si no está dentro. */
function relDir(base: string, dir: string): string | undefined {
  const b = slash(base).replace(/\/+$/, '');
  const d = slash(dir).replace(/\/+$/, '');
  const cmp = (x: string) => (/^[A-Za-z]:\//.test(x) ? x.toLowerCase() : x);
  if (cmp(d) === cmp(b)) return '';
  return cmp(d).startsWith(cmp(b) + '/') ? d.slice(b.length + 1) : undefined;
}

export function detectStack(files: ProjectFile[], opts: DetectOptions): ProjectStack {
  const byDir = new Map<string, Map<string, ProjectFile>>();
  for (const f of files) {
    const d = dirOf(f.path);
    if (!byDir.has(d)) byDir.set(d, new Map());
    byDir.get(d)!.set(baseOf(f.path), f);
  }
  const want = new Set(opts.ecosystems);
  const deps: Dependency[] = [];
  const runtimes: RuntimeTarget[] = [];
  const sdks: SdkInfo[] = [];
  const manifests: string[] = [];

  if (want.has('npm')) deps.push(...detectNpm(byDir, opts, manifests));
  if (want.has('nuget')) {
    const r = detectNuget(files, byDir, opts, manifests);
    deps.push(...r.deps);
    runtimes.push(...r.runtimes);
    sdks.push(...r.sdks);
  }
  if (want.has('pip')) deps.push(...detectPython(byDir, opts, manifests));

  const ecosystems = [...new Set(deps.map(d => d.ecosystem))];
  if (runtimes.length && !ecosystems.includes('nuget')) ecosystems.push('nuget');
  return { ecosystems, dependencies: deps, runtimes: dedupeRuntimes(runtimes), sdks, manifests };
}

// ---------- npm ----------
function detectNpm(byDir: Map<string, Map<string, ProjectFile>>, opts: DetectOptions, manifests: string[]): Dependency[] {
  const out: Dependency[] = [];
  const lockCache = new Map<string, NpmLock | undefined>();
  const flatCache = new Map<string, Dependency[]>();

  /** Lockfile más cercano hacia arriba. */
  const findLock = (dir: string): ProjectFile | undefined => {
    for (let d = dir; ; d = dirOf(d)) {
      const files = byDir.get(d);
      const lock = files?.get('package-lock.json') ?? files?.get('npm-shrinkwrap.json')
        ?? files?.get('yarn.lock') ?? files?.get('pnpm-lock.yaml');
      if (lock) return lock;
      if (dirOf(d) === d) return undefined;
    }
  };

  for (const [dir, files] of byDir) {
    const pkg = files.get('package.json');
    if (!pkg || /[\\/]node_modules[\\/]/.test(pkg.path)) continue;
    manifests.push(pkg.path);
    const direct = parsePackageJson(pkg.path, pkg.text);
    const directNames = [...new Set(direct.map(d => d.name))];
    const lock = findLock(dir);
    if (!lock) { out.push(...direct); continue; }

    const lockName = baseOf(lock.path);
    if (lockName === 'package-lock.json' || lockName === 'npm-shrinkwrap.json') {
      if (!lockCache.has(lock.path)) {
        lockCache.set(lock.path, parsePackageLockTree(lock.path, lock.text));
        manifests.push(lock.path);
      }
      const tree = lockCache.get(lock.path);
      const ws = relDir(dirOf(lock.path), dir);
      if (!tree || ws === undefined) { out.push(...direct); continue; }
      // Cada workspace recibe la versión que le corresponde por su ruta en el árbol.
      const res = resolveWorkspace(tree, ws, directNames);
      for (const d of direct) {
        const e = res.direct.get(d.name);
        out.push(e ? { ...d, version: e.version, approximate: false } : d);
      }
      if (opts.includeTransitive) {
        for (const e of res.transitive) out.push(lockEntryToDependency(tree, e, false));
      }
      continue;
    }

    // yarn.lock / pnpm-lock.yaml: índice por nombre. Si un nombre tiene varias
    // versiones no se elige una al azar: queda sin determinar (se usa el rango).
    if (!flatCache.has(lock.path)) {
      flatCache.set(lock.path, lockName === 'yarn.lock'
        ? parseYarnLock(lock.path, lock.text, new Set(directNames))
        : parsePnpmLock(lock.path, lock.text, new Set(directNames)));
      manifests.push(lock.path);
    }
    const flat = flatCache.get(lock.path)!;
    const versions = new Map<string, Set<string>>();
    for (const l of flat) {
      if (!versions.has(l.name)) versions.set(l.name, new Set());
      versions.get(l.name)!.add(l.version!);
    }
    for (const d of direct) {
      const vs = versions.get(d.name);
      out.push(vs && vs.size === 1 ? { ...d, version: [...vs][0], approximate: false } : d);
    }
    if (opts.includeTransitive && lock.path === (byDir.get(dir)?.get(lockFileName(files)))?.path) {
      for (const l of flat) {
        const vs = versions.get(l.name);
        if (!directNames.includes(l.name) || (vs && vs.size > 1)) out.push({ ...l, direct: false });
      }
    }
  }
  return dedupe(out);
}
function lockFileName(files: Map<string, ProjectFile>): string {
  return ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'].find(n => files.has(n)) ?? '';
}

// ---------- NuGet / .NET ----------
function detectNuget(files: ProjectFile[], byDir: Map<string, Map<string, ProjectFile>>, opts: DetectOptions, manifests: string[]) {
  const deps: Dependency[] = [];
  const runtimes: RuntimeTarget[] = [];
  const sdks: SdkInfo[] = [];

  // Versiones centrales (Directory.Packages.props), del más cercano hacia arriba.
  const centralCache = new Map<string, Map<string, Dependency>>();
  const centralFor = (dir: string): Map<string, Dependency> | undefined => {
    for (let d = dir; ; d = dirOf(d)) {
      const f = byDir.get(d)?.get('directory.packages.props');
      if (f) {
        if (!centralCache.has(f.path)) {
          const r = parseMsBuildProject(f.path, f.text);
          centralCache.set(f.path, new Map(r.dependencies.map(x => [x.name.toLowerCase(), x])));
          manifests.push(f.path);
        }
        return centralCache.get(f.path);
      }
      if (dirOf(d) === d) return undefined;
    }
  };

  for (const f of files) {
    const base = baseOf(f.path);
    if (base === 'global.json') { sdks.push(...parseGlobalJson(f.path, f.text)); manifests.push(f.path); continue; }
    if (!/\.(cs|fs|vb)proj$/.test(base) && base !== 'directory.build.props') continue;
    manifests.push(f.path);
    const r = parseMsBuildProject(f.path, f.text);
    runtimes.push(...r.runtimes);
    const central = centralFor(dirOf(f.path));
    const projectDeps = [...r.dependencies];
    for (const name of r.centrallyManaged) {
      const c = central?.get(name.toLowerCase());
      if (c) projectDeps.push({ ...c, direct: true });
    }
    const lockFile = byDir.get(dirOf(f.path))?.get('packages.lock.json');
    if (lockFile) {
      manifests.push(lockFile.path);
      const lock = parseNugetLock(lockFile.path, lockFile.text);
      const resolved = new Map(lock.map(l => [l.name.toLowerCase(), l]));
      for (const d of projectDeps) {
        const l = resolved.get(d.name.toLowerCase());
        deps.push(l ? { ...d, version: l.version, approximate: false } : d);
      }
      if (opts.includeTransitive) deps.push(...lock.filter(l => !l.direct));
    } else {
      deps.push(...projectDeps);
    }
    // Paquetes Microsoft.AspNetCore.* explícitos: evidencia débil de ASP.NET Core
    for (const d of projectDeps) {
      const mm = d.version && /^(\d+)\.(\d+)/.exec(d.version);
      if (mm && /^Microsoft\.AspNetCore\./i.test(d.name) && parseInt(mm[1], 10) >= 5) {
        runtimes.push({
          product: 'ASP.NET Core', band: `${mm[1]}.${mm[2]}`, app: f.path.split(/[\\/]/).pop()!, appKind: 'implied',
          evidence: `paquete ${d.name}`, source: `paquete ${d.name}`, location: d.location,
        });
      }
    }
  }

  // runtimeconfig.json (salida de compilación): evidencia directa de la versión solicitada,
  // de si la aplicación es autocontenida y de la política de roll-forward.
  for (const f of files) {
    if (!/\.runtimeconfig\.json$/i.test(f.path)) continue;
    const rc = parseRuntimeConfig(f.path, f.text);
    if (!rc) continue;
    manifests.push(f.path);
    const tfm = rc.tfm ? /^net(?:coreapp)?(\d+\.\d+)/.exec(rc.tfm)?.[1] : undefined;
    for (const t of runtimes) {
      const appName = t.app.replace(/\.(cs|fs|vb)proj$/i, '').toLowerCase();
      if (t.appKind === 'implied' || appName !== rc.assembly.toLowerCase() || (tfm && tfm !== t.band)) continue;
      const v = rc.selfContained ? rc.includedVersion : rc.frameworkVersion;
      if (v && v.startsWith(t.band + '.')) { t.version = v; t.evidence = `${f.path.split(/[\\/]/).pop()}`; }
      if (rc.selfContained) t.selfContained = true;
      if (rc.rollForward) t.rollForward = rc.rollForward;
    }
  }
  return { deps: dedupe(deps), runtimes, sdks };
}

// ---------- Python ----------
function detectPython(byDir: Map<string, Map<string, ProjectFile>>, opts: DetectOptions, manifests: string[]): Dependency[] {
  const out: Dependency[] = [];
  for (const [, files] of byDir) {
    const direct: Dependency[] = [];
    for (const [name, f] of files) {
      if (/^requirements.*\.txt$/.test(name)) { direct.push(...parseRequirements(f.path, f.text)); manifests.push(f.path); }
      else if (name === 'pyproject.toml') { direct.push(...parsePyproject(f.path, f.text)); manifests.push(f.path); }
      else if (name === 'pipfile') { direct.push(...parsePipfile(f.path, f.text)); manifests.push(f.path); }
    }
    const directNames = new Set(direct.map(d => normalizeName('pip', d.name)));
    const lockF = files.get('poetry.lock') ?? files.get('uv.lock') ?? files.get('pipfile.lock');
    if (!lockF) { out.push(...direct); continue; }
    manifests.push(lockF.path);
    const lock = baseOf(lockF.path) === 'pipfile.lock'
      ? parsePipfileLock(lockF.path, lockF.text, directNames)
      : parseTomlLock(lockF.path, lockF.text, directNames);
    const resolved = new Map(lock.map(l => [normalizeName('pip', l.name), l.version!]));
    for (const d of direct) {
      const v = resolved.get(normalizeName('pip', d.name));
      out.push(v ? { ...d, version: v, approximate: false } : d);
    }
    // Sin manifiesto no se distingue directas de transitivas: se incluye todo el lockfile
    // para no producir un escaneo vacío.
    const canDistinguish = direct.length > 0;
    for (const l of lock) {
      if (directNames.has(normalizeName('pip', l.name))) continue;
      if (opts.includeTransitive || l.direct || !canDistinguish) out.push(l);
    }
  }
  return dedupe(out);
}

function dedupe(deps: Dependency[]): Dependency[] {
  const seen = new Set<string>();
  return deps.filter(d => {
    const k = `${d.ecosystem}|${normalizeName(d.ecosystem, d.name)}|${d.version}|${d.declared}|${d.location.file}|${d.location.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function dedupeRuntimes(rs: RuntimeTarget[]): RuntimeTarget[] {
  const seen = new Set<string>();
  // Los runtimes deducidos de un paquete ceden ante los de un proyecto (TFM) en el mismo archivo.
  const sorted = [...rs].sort((a, b) => Number(a.appKind === 'implied') - Number(b.appKind === 'implied'));
  return sorted.filter(r => {
    const k = `${r.product}|${r.band}|${r.location.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
