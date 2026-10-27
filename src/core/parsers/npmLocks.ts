import { Dependency } from '../types';
import { locate } from '../text';

/** yarn.lock (v1 clásico y Berry). */
export function parseYarnLock(file: string, text: string, directNames: Set<string>): Dependency[] {
  const out: Dependency[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  let current: { name: string; offset: number; len: number } | undefined;
  let offset = 0;
  for (const line of lines) {
    if (line && !line.startsWith(' ') && !line.startsWith('#') && line.trimEnd().endsWith(':')) {
      const firstSpec = line.split(',')[0].replace(/^"|"?:?\s*$/g, '').replace(/"$/, '');
      const at = firstSpec.lastIndexOf('@');
      const name = at > 0 ? firstSpec.slice(0, at) : firstSpec;
      current = name && name !== '__metadata' ? { name, offset, len: line.length } : undefined;
    } else if (current) {
      const m = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
      if (m) {
        const id = `${current.name}@${m[1]}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push({
            ecosystem: 'npm', name: current.name, version: m[1],
            direct: directNames.has(current.name),
            location: locate(text, file, current.offset, current.len),
          });
        }
        current = undefined;
      }
    }
    offset += line.length + 1;
  }
  return out;
}

/** pnpm-lock.yaml (v5–v9): claves de la sección "packages:". */
export function parsePnpmLock(file: string, text: string, directNames: Set<string>): Dependency[] {
  const out: Dependency[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);
  let inPackages = false;
  let offset = 0;
  for (const line of lines) {
    if (/^\S/.test(line)) inPackages = /^(packages|snapshots):\s*$/.test(line);
    else if (inPackages) {
      const m = /^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@\s'"(/]+)[@/]([0-9][^(:'"\s_]*)/.exec(line);
      if (m) {
        const id = `${m[1]}@${m[2]}`;
        if (!seen.has(id)) {
          seen.add(id);
          out.push({
            ecosystem: 'npm', name: m[1], version: m[2], direct: directNames.has(m[1]),
            location: locate(text, file, offset, line.length),
          });
        }
      }
    }
    offset += line.length + 1;
  }
  return out;
}
