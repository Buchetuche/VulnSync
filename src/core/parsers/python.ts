import { Dependency } from '../types';
import { locate } from '../text';
import { exactPin, lowerBoundOf } from '../version';

const REQ_LINE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*((?:[<>=!~]=?|===)\s*[^;#\s,]+(?:\s*,\s*(?:[<>=!~]=?|===)\s*[^;#\s,]+)*)?/;

/** Una especificación PEP 508 ("requests[socks]>=2.31,<3 ; python_version>'3.8'"). */
function specToDep(file: string, text: string, spec: string, offset: number, direct: boolean): Dependency | undefined {
  const m = REQ_LINE.exec(spec);
  if (!m) return undefined;
  const name = m[1];
  const declared = (m[3] ?? '').replace(/\s+/g, '');
  const pin = declared ? exactPin(declared, 'pip') : undefined;
  const lower = declared && !pin ? lowerBoundOf(declared.replace(/^~=|^>=|^==/, ''), 'pip') : undefined;
  const hasLower = /(^|,)(>=|~=|==)/.test(declared);
  const versionText = m[3] ?? name;
  const colInSpec = spec.indexOf(versionText);
  return {
    ecosystem: 'pip', name, declared: declared || undefined, direct,
    version: pin ?? (hasLower ? lower : undefined),
    approximate: !pin,
    location: locate(text, file, offset + Math.max(colInSpec, 0), versionText.length),
  };
}

/** requirements*.txt (ignora -r, -e, URLs y opciones). */
export function parseRequirements(file: string, text: string): Dependency[] {
  const out: Dependency[] = [];
  let offset = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, '');
    if (line.trim() && !/^\s*(-|#|https?:|git\+)/.test(line) && !line.includes(' @ ')) {
      const d = specToDep(file, text, line, offset, true);
      if (d) out.push(d);
    }
    offset += rawLine.length + 1;
  }
  return out;
}

/**
 * pyproject.toml: [project].dependencies, [project.optional-dependencies],
 * [dependency-groups] y [tool.poetry.*dependencies]. Parser TOML mínimo.
 */
export function parsePyproject(file: string, text: string): Dependency[] {
  const out: Dependency[] = [];
  let section = '';
  let inArray = false;
  let offset = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/(^|\s)#.*$/, '');
    const sec = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (sec) { section = sec[1].trim(); inArray = false; offset += raw.length + 1; continue; }

    const pep621 = section === 'project' || section === 'project.optional-dependencies' || section === 'dependency-groups';
    if (pep621) {
      if (/^\s*[\w-]+\s*=\s*\[/.test(line) && (section !== 'project' || /^\s*dependencies\s*=/.test(line))) inArray = true;
      if (inArray) {
        const strRe = /"([^"]+)"|'([^']+)'/g;
        let m: RegExpExecArray | null;
        while ((m = strRe.exec(line))) {
          const spec = m[1] ?? m[2];
          const d = specToDep(file, text, spec, offset + m.index + 1, true);
          if (d) out.push(d);
        }
        if (line.includes(']')) inArray = false;
      }
    } else if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)$/.test(section)) {
      // name = "^1.2.3"  |  name = { version = "^1.2", extras = [...] }
      const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/.exec(line);
      if (m && m[1].toLowerCase() !== 'python') {
        const declared = m[2] ?? m[3];
        const pin = /^\d[\w.]*$/.test(declared) || declared.startsWith('==') ? declared.replace(/^==/, '') : undefined;
        out.push({
          ecosystem: 'pip', name: m[1], declared, direct: true,
          version: pin ?? lowerBoundOf(declared.replace(/^[\^~>=]+/, ''), 'pip'),
          approximate: !pin,
          location: locate(text, file, offset + line.indexOf(declared), declared.length),
        });
      }
    }
    offset += raw.length + 1;
  }
  return out;
}

/** poetry.lock y uv.lock: bloques [[package]] con name/version. */
export function parseTomlLock(file: string, text: string, directNames: Set<string>): Dependency[] {
  const out: Dependency[] = [];
  const blockRe = /\[\[package\]\]\s*\r?\nname\s*=\s*"([^"]+)"\s*\r?\nversion\s*=\s*"([^"]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = blockRe.exec(text))) {
    const norm = m[1].toLowerCase().replace(/[-_.]+/g, '-');
    out.push({
      ecosystem: 'pip', name: m[1], version: m[2], direct: directNames.has(norm),
      location: locate(text, file, m.index + m[0].lastIndexOf(m[2]), m[2].length),
    });
  }
  return out;
}

/** Pipfile.lock (JSON): default/develop → "==1.2.3". */
export function parsePipfileLock(file: string, text: string, directNames: Set<string>): Dependency[] {
  let json: any;
  try { json = JSON.parse(text); } catch { return []; }
  const out: Dependency[] = [];
  for (const group of ['default', 'develop']) {
    for (const [name, info] of Object.entries<any>(json?.[group] ?? {})) {
      const v = typeof info?.version === 'string' ? info.version.replace(/^==/, '') : undefined;
      if (!v) continue;
      const needle = `"${name}"`;
      const i = text.indexOf(needle);
      out.push({
        ecosystem: 'pip', name, version: v,
        direct: directNames.has(name.toLowerCase().replace(/[-_.]+/g, '-')),
        location: locate(text, file, Math.max(i, 0), needle.length),
      });
    }
  }
  return out;
}
