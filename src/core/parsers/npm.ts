import { Dependency } from '../types';
import { locate, locateNeedle } from '../text';
import { exactPin, lowerBoundOf } from '../version';

const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

/** package.json → dependencias directas con su rango declarado. */
export function parsePackageJson(file: string, text: string): Dependency[] {
  let json: any;
  try { json = JSON.parse(text); } catch { return []; }
  const out: Dependency[] = [];
  for (const section of DEP_SECTIONS) {
    const deps = json?.[section];
    if (!deps || typeof deps !== 'object') continue;
    const sectionIdx = text.indexOf(`"${section}"`);
    for (const [name, raw] of Object.entries<string>(deps)) {
      if (typeof raw !== 'string') continue;
      // Ubicar  "name": "range"  dentro de la sección
      const re = new RegExp(`"${escapeRe(name)}"\\s*:\\s*"(${escapeRe(raw)})"`, 'g');
      re.lastIndex = Math.max(sectionIdx, 0);
      const m = re.exec(text);
      const loc = m
        ? locate(text, file, m.index + m[0].length - raw.length - 1, raw.length)
        : locateNeedle(text, file, `"${name}"`);
      const pin = exactPin(raw, 'npm');
      out.push({
        ecosystem: 'npm', name, declared: raw, direct: true, location: loc,
        version: pin ?? lowerBoundOf(raw, 'npm'),
        approximate: !pin,
      });
    }
  }
  return out;
}

export interface NpmLockEntry {
  /** Ruta dentro del lockfile ("node_modules/a/node_modules/b", "apps/web"). */
  path: string;
  name: string;
  version: string;
  /** true para enlaces de workspace (no son paquetes del registro). */
  link: boolean;
  /** Nombres de dependencias (incluye devDependencies solo en workspaces/raíz). */
  deps: string[];
}

export interface NpmLock {
  file: string;
  text: string;
  entries: Map<string, NpmLockEntry>;
}

const nameFromPath = (key: string) => {
  const i = key.lastIndexOf('node_modules/');
  return i < 0 ? key : key.slice(i + 'node_modules/'.length);
};

/**
 * package-lock.json (v2/3: mapa "packages"; v1: "dependencies" anidado, que se
 * convierte a rutas equivalentes). Conserva TODAS las versiones de cada paquete.
 */
export function parsePackageLockTree(file: string, text: string): NpmLock | undefined {
  let json: any;
  try { json = JSON.parse(text); } catch { return undefined; }
  const entries = new Map<string, NpmLockEntry>();
  if (json?.packages && typeof json.packages === 'object') {
    for (const [key, info] of Object.entries<any>(json.packages)) {
      if (!info || typeof info !== 'object') continue;
      const isLink = !!info.link;
      if (key !== '' && !isLink && typeof info.version !== 'string') continue;
      const deps = new Set<string>();
      for (const sec of ['dependencies', 'optionalDependencies', 'peerDependencies', ...(key.includes('node_modules/') ? [] : ['devDependencies'])]) {
        for (const n of Object.keys(info[sec] ?? {})) deps.add(n);
      }
      entries.set(key, {
        path: key, name: info.name ?? nameFromPath(key), version: info.version ?? '',
        link: isLink, deps: [...deps],
      });
    }
  } else if (json?.dependencies && typeof json.dependencies === 'object') {
    const rootDeps = Object.keys(json.dependencies);
    entries.set('', { path: '', name: json.name ?? '', version: json.version ?? '', link: false, deps: rootDeps });
    const walk = (deps: any, prefix: string) => {
      for (const [name, info] of Object.entries<any>(deps)) {
        if (typeof info?.version !== 'string') continue;
        const path = `${prefix}node_modules/${name}`;
        entries.set(path, { path, name, version: info.version, link: false, deps: Object.keys(info.requires ?? {}) });
        if (info.dependencies) walk(info.dependencies, `${path}/`);
      }
    };
    walk(json.dependencies, '');
  } else return undefined;
  return { file, text, entries };
}

/** Directorio contenedor en el árbol de instalación (como lo recorre Node). */
function parentBase(p: string): string | undefined {
  if (p === '') return undefined;
  const m = /^(.*?)(?:^|\/)node_modules\/(?:@[^/]+\/)?[^/]+$/.exec(p);
  if (m) return m[1];
  const i = p.lastIndexOf('/');
  return i < 0 ? '' : p.slice(0, i);
}

/** Resuelve `name` desde `from` buscando node_modules hacia arriba, igual que Node. */
export function resolveFrom(lock: NpmLock, from: string, name: string): NpmLockEntry | undefined {
  let base: string | undefined = from;
  while (base !== undefined) {
    const e = lock.entries.get(`${base ? base + '/' : ''}node_modules/${name}`);
    if (e) return e;
    base = parentBase(base);
  }
  return undefined;
}

export interface WorkspaceResolution {
  direct: Map<string, NpmLockEntry>;
  /** Cierre transitivo (sin las directas) alcanzable desde este workspace. */
  transitive: NpmLockEntry[];
  /** Directas que no pudieron resolverse sin ambigüedad. */
  unresolved: string[];
}

/** Versiones de un workspace según su ruta dentro del lockfile. */
export function resolveWorkspace(lock: NpmLock, workspacePath: string, directNames: string[]): WorkspaceResolution {
  const direct = new Map<string, NpmLockEntry>();
  const unresolved: string[] = [];
  const queue: NpmLockEntry[] = [];
  for (const n of directNames) {
    const e = resolveFrom(lock, workspacePath, n);
    if (e && !e.link && e.version) { direct.set(n, e); queue.push(e); } else unresolved.push(n);
  }
  const seen = new Set<string>(queue.map(e => e.path));
  const transitive: NpmLockEntry[] = [];
  const directPaths = new Set(queue.map(e => e.path));
  while (queue.length) {
    const cur = queue.shift()!;
    for (const dn of cur.deps) {
      const e = resolveFrom(lock, cur.path, dn);
      if (!e || e.link || !e.version || seen.has(e.path)) continue;
      seen.add(e.path);
      transitive.push(e);
      queue.push(e);
    }
  }
  return { direct, transitive: transitive.filter(e => !directPaths.has(e.path)), unresolved };
}

/** Dependencia (con ubicación en el lockfile) a partir de una entrada. */
export function lockEntryToDependency(lock: NpmLock, e: NpmLockEntry, direct: boolean): Dependency {
  const needle = lock.text.includes(`"${e.path}"`) ? `"${e.path}"` : `"${e.name}"`;
  return { ecosystem: 'npm', name: e.name, version: e.version, direct, location: locateNeedle(lock.text, lock.file, needle) };
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
