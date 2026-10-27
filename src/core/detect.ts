// Detección del stack a partir de los archivos del proyecto.
// Recibe contenidos ya leídos para que sea independiente de VS Code.

import { Dependency, Ecosystem, ProjectStack, RuntimeTarget } from './types';
import { normalizeName } from './text';
import { parsePackageJson, parsePackageLock } from './parsers/npm';
import { parsePnpmLock, parseYarnLock } from './parsers/npmLocks';
import { parseGlobalJson, parseMsBuildProject, parseNugetLock } from './parsers/nuget';
import { parsePipfileLock, parsePyproject, parseRequirements, parseTomlLock } from './parsers/python';

export interface ProjectFile { path: string; text: string; }
export interface DetectOptions { ecosystems: Ecosystem[]; includeTransitive: boolean; }

/** Patrones glob que el host debe leer para llamar a detectStack. */
export const MANIFEST_GLOB =
  '**/{package.json,package-lock.json,npm-shrinkwrap.json,yarn.lock,pnpm-lock.yaml,' +
  '*.csproj,*.fsproj,*.vbproj,Directory.Packages.props,Directory.Build.props,packages.lock.json,global.json,' +
  'requirements*.txt,pyproject.toml,poetry.lock,uv.lock,Pipfile.lock}';

const dirOf = (p: string) => p.replace(/[\\/][^\\/]*$/, '');
const baseOf = (p: string) => p.split(/[\\/]/).pop()!.toLowerCase();

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
  const manifests: string[] = [];

  if (want.has('npm')) deps.push(...detectNpm(byDir, opts, manifests));
  if (want.has('nuget')) {
    const r = detectNuget(files, byDir, opts, manifests);
    deps.push(...r.deps);
    runtimes.push(...r.runtimes);
  }
  if (want.has('pip')) deps.push(...detectPython(byDir, opts, manifests));

  const ecosystems = [...new Set(deps.map(d => d.ecosystem))];
  if (runtimes.length && !ecosystems.includes('nuget')) ecosystems.push('nuget');
  return { ecosystems, dependencies: deps, runtimes: dedupeRuntimes(runtimes), manifests };
}

// ---------- npm ----------
function detectNpm(byDir: Map<string, Map<string, ProjectFile>>, opts: DetectOptions, manifests: string[]): Dependency[] {
  const out: Dependency[] = [];
  const lockCache = new Map<string, Dependency[]>();

  const lockFor = (dir: string, direct: Set<string>): Dependency[] | undefined => {
    for (let d = dir; ; d = dirOf(d)) {
      const files = byDir.get(d);
      const lock = files?.get('package-lock.json') ?? files?.get('npm-shrinkwrap.json')
        ?? files?.get('yarn.lock') ?? files?.get('pnpm-lock.yaml');
      if (lock) {
        if (!lockCache.has(lock.path)) {
          const name = baseOf(lock.path);
          const parsed = name === 'yarn.lock' ? parseYarnLock(lock.path, lock.text, direct)
            : name === 'pnpm-lock.yaml' ? parsePnpmLock(lock.path, lock.text, direct)
            : parsePackageLock(lock.path, lock.text, direct);
          lockCache.set(lock.path, parsed);
          manifests.push(lock.path);
        }
        return lockCache.get(lock.path);
      }
      if (dirOf(d) === d) return undefined;
    }
  };

  for (const [dir, files] of byDir) {
    const pkg = files.get('package.json');
    if (!pkg || /[\\/]node_modules[\\/]/.test(pkg.path)) continue;
    manifests.push(pkg.path);
    const direct = parsePackageJson(pkg.path, pkg.text);
    const directNames = new Set(direct.map(d => d.name));
    const lock = lockFor(dir, directNames);
    if (!lock) { out.push(...direct); continue; }

    const resolved = new Map<string, string>();
    for (const l of lock) if (!resolved.has(l.name)) resolved.set(l.name, l.version!);
    for (const d of direct) {
      const v = resolved.get(d.name);
      out.push(v ? { ...d, version: v, approximate: false } : d);
    }
    if (opts.includeTransitive && byDir.get(dir)?.has(lockFileName(files))) {
      for (const l of lock) if (!directNames.has(l.name) || resolved.get(l.name) !== l.version) out.push({ ...l, direct: false });
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
    if (base === 'global.json') { runtimes.push(...parseGlobalJson(f.path, f.text)); manifests.push(f.path); continue; }
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
    // Paquetes Microsoft.AspNetCore.* explícitos implican ASP.NET Core
    for (const d of projectDeps) {
      const mm = d.version && /^(\d+)\.(\d+)/.exec(d.version);
      if (mm && /^Microsoft\.AspNetCore\./i.test(d.name) && parseInt(mm[1], 10) >= 5) {
        runtimes.push({ product: 'ASP.NET Core', band: `${mm[1]}.${mm[2]}`, source: `paquete ${d.name}`, location: d.location });
      }
    }
  }
  return { deps: dedupe(deps), runtimes };
}

// ---------- Python ----------
function detectPython(byDir: Map<string, Map<string, ProjectFile>>, opts: DetectOptions, manifests: string[]): Dependency[] {
  const out: Dependency[] = [];
  for (const [, files] of byDir) {
    const direct: Dependency[] = [];
    for (const [name, f] of files) {
      if (/^requirements.*\.txt$/.test(name)) { direct.push(...parseRequirements(f.path, f.text)); manifests.push(f.path); }
      else if (name === 'pyproject.toml') { direct.push(...parsePyproject(f.path, f.text)); manifests.push(f.path); }
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
    for (const l of lock) {
      if (directNames.has(normalizeName('pip', l.name))) continue;
      if (opts.includeTransitive || l.direct) out.push(l);
    }
  }
  return dedupe(out);
}

function dedupe(deps: Dependency[]): Dependency[] {
  const seen = new Set<string>();
  return deps.filter(d => {
    const k = `${d.ecosystem}|${normalizeName(d.ecosystem, d.name)}|${d.version}|${d.location.file}|${d.location.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function dedupeRuntimes(rs: RuntimeTarget[]): RuntimeTarget[] {
  const seen = new Set<string>();
  return rs.filter(r => {
    const k = `${r.product}|${r.band}|${r.location.file}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}
