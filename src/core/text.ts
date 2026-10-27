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
