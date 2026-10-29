import { SourceLocation } from './types';

/** Convierte un offset absoluto del texto en línea/columna (0-based). */
export function locate(text: string, file: string, offset: number, length: number): SourceLocation {
  let line = 0;
  let lineStart = 0;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) { line++; lineStart = i + 1; }
  }
  const startCol = offset - lineStart;
  return { file, line, startCol, endCol: startCol + Math.max(length, 1) };
}

/** Ubica la primera aparición de `needle` a partir de `from`; si no existe, línea 0. */
export function locateNeedle(text: string, file: string, needle: string, from = 0): SourceLocation {
  const i = text.indexOf(needle, from);
  return i < 0 ? { file, line: 0, startCol: 0, endCol: 1 } : locate(text, file, i, needle.length);
}

/** Nombre normalizado de paquete según el ecosistema. */
export function normalizeName(eco: string, name: string): string {
  if (eco === 'pip') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (eco === 'nuget') return name.toLowerCase();
  return name;
}

// ---------- Markdown seguro (VS-013) ----------

/** Escapa texto externo para que se renderice como texto plano en Markdown. */
export function escapeMd(s: string): string {
  return String(s)
    .replace(/\r?\n|\r/g, ' ')
    .replace(/[\\`*_{}\[\]()#+!|<>~&]/g, c => `\\${c}`);
}

/** Texto dentro de un span de código, con una cerca más larga que cualquier racha de backticks. */
export function codeSpan(s: string): string {
  const t = String(s).replace(/\r?\n|\r/g, ' ');
  const runs = t.match(/`+/g) ?? [];
  const fence = '`'.repeat(Math.max(0, ...runs.map(r => r.length)) + 1);
  const pad = t.startsWith('`') || t.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${t}${pad}${fence}`;
}

/** Devuelve la URL normalizada solo si es http(s); si no, undefined. */
export function safeUrl(u: string | undefined): string | undefined {
  if (!u) return undefined;
  try {
    const url = new URL(u);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
    return url.href.replace(/[()\s<>]/g, c => encodeURIComponent(c));
  } catch { return undefined; }
}

/** Enlace Markdown seguro; si la URL no es válida devuelve solo el texto escapado. */
export function mdLink(label: string, url: string | undefined): string {
  const safe = safeUrl(url);
  return safe ? `[${escapeMd(label)}](${safe})` : escapeMd(label);
}

// ---------- Rutas relativas por carpeta de workspace (VS-011) ----------

export interface RootFolder { name: string; path: string; }

const norm = (p: string) => p.replace(/\\/g, '/').replace(/\/+$/, '');
const sameCase = (p: string) => (/^[A-Za-z]:\//.test(p) ? p.toLowerCase() : p);

/**
 * Ruta relativa a su carpeta de workspace. Con varias carpetas antepone el
 * nombre de la carpeta. Nunca devuelve rutas absolutas.
 */
export function relativeToRoots(file: string, roots: RootFolder[] | string): string {
  const list: RootFolder[] = typeof roots === 'string'
    ? (roots ? [{ name: '', path: roots }] : [])
    : roots;
  const f = norm(file);
  let best: RootFolder | undefined;
  for (const r of list) {
    const rp = norm(r.path);
    if (!rp) continue;
    if ((sameCase(f) === sameCase(rp) || sameCase(f).startsWith(sameCase(rp) + '/'))
      && (!best || rp.length > norm(best.path).length)) best = r;
  }
  if (!best) return `…/${f.split('/').pop() ?? f}`;
  const rel = f.slice(norm(best.path).length).replace(/^\//, '');
  return list.length > 1 && best.name ? `${best.name}/${rel}` : rel;
}
