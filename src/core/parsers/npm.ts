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

/**
 * package-lock.json (lockfileVersion 2/3: mapa "packages") o v1 ("dependencies").
 * Devuelve todas las versiones resueltas; `directNames` marca las directas.
 */
export function parsePackageLock(file: string, text: string, directNames: Set<string>): Dependency[] {
  let json: any;
  try { json = JSON.parse(text); } catch { return []; }
  const out: Dependency[] = [];
  const seen = new Set<string>();
  const push = (name: string, version: string, key: string) => {
    const id = `${name}@${version}`;
    if (!name || !version || seen.has(id)) return;
    seen.add(id);
    out.push({
      ecosystem: 'npm', name, version, direct: directNames.has(name),
      location: locateNeedle(text, file, `"${key}"`),
    });
  };
  if (json?.packages && typeof json.packages === 'object') {
    for (const [key, info] of Object.entries<any>(json.packages)) {
      if (!key || info?.link || typeof info?.version !== 'string') continue;
      const name = info.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      push(name, info.version, key);
    }
  } else if (json?.dependencies) {
    const walk = (deps: any) => {
      for (const [name, info] of Object.entries<any>(deps)) {
        if (typeof info?.version === 'string') push(name, info.version, name);
        if (info?.dependencies) walk(info.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}
