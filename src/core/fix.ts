// Planificación de correcciones automáticas. Regla de oro: una corrección
// automática nunca amplía el conjunto de versiones permitido por el rango original.
// Solo se editan pines y rangos simples; el resto se devuelve como sugerencia.

import { Ecosystem } from './types';
import { compareVersions, declaredToIntervals } from './version';

export type UpgradePlan =
  | { kind: 'edit'; text: string }
  | { kind: 'suggest'; reason: string }
  | { kind: 'none' };

/** Límite superior (inclusive o no) del rango, para comprobar que no se amplía. */
function upperOf(range: string, eco: Ecosystem): string | undefined | 'none' {
  const iv = declaredToIntervals(range, eco);
  if (!iv || iv.length !== 1) return 'none';
  return iv[0].hi;
}

function sameUpper(oldRange: string, newRange: string, eco: Ecosystem): boolean {
  const a = upperOf(oldRange, eco);
  const b = upperOf(newRange, eco);
  if (a === 'none' || b === 'none') return false;
  if (a === undefined || b === undefined) return a === b;
  return compareVersions(a, b) === 0;
}

const suggest = (current: string, fixed: string): UpgradePlan => ({
  kind: 'suggest',
  reason: `El rango "${current}" es complejo o la versión corregida ${fixed} queda fuera de él. ` +
    'Edita el rango manualmente conservando sus límites superiores y alternativas.',
});

/**
 * @param current texto actual de la versión declarada (el rango tal cual está en el manifiesto)
 * @param fixed   primera versión corregida
 */
export function planUpgrade(eco: Ecosystem, current: string, fixed: string): UpgradePlan {
  const cur = current.trim();
  if (!fixed || !cur) return { kind: 'none' };

  if (eco === 'npm') {
    const m = /^(\^|~|=)?\s*v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)$/.exec(cur);
    if (!m) return suggest(cur, fixed);
    const [, op = '', ver] = m;
    if (compareVersions(fixed, ver) <= 0) return { kind: 'none' };
    const next = op + fixed;
    if ((op === '^' || op === '~') && !sameUpper(cur, next, 'npm')) return suggest(cur, fixed);
    return { kind: 'edit', text: next };
  }

  if (eco === 'nuget') {
    const br = /^\[\s*([^,\]\s]+)\s*\]$/.exec(cur);
    if (br) return compareVersions(fixed, br[1]) > 0 ? { kind: 'edit', text: `[${fixed}]` } : { kind: 'none' };
    // "1.2.3" = ">= 1.2.3": subir el mínimo solo estrecha el rango.
    if (/^\d+(\.\d+){0,3}(-[0-9A-Za-z.\-]+)?$/.test(cur)) {
      return compareVersions(fixed, cur) > 0 ? { kind: 'edit', text: fixed } : { kind: 'none' };
    }
    return suggest(cur, fixed);
  }

  // pip (PEP 440, Poetry y Pipfile)
  let m = /^(===?)\s*(\S+)$/.exec(cur);
  if (m && !m[2].includes('*')) return compareVersions(fixed, m[2]) > 0 ? { kind: 'edit', text: `${m[1]}${fixed}` } : { kind: 'none' };
  m = /^>=\s*([^\s,]+)$/.exec(cur);                     // sin límite superior: subir el mínimo estrecha
  if (m) return compareVersions(fixed, m[1]) > 0 ? { kind: 'edit', text: `>=${fixed}` } : { kind: 'none' };
  m = /^(~=|\^|~)\s*(\d[^\s,]*)$/.exec(cur);
  if (m) {
    if (compareVersions(fixed, m[2]) <= 0) return { kind: 'none' };
    const next = `${m[1]}${fixed}`;
    return sameUpper(cur, next, 'pip') ? { kind: 'edit', text: next } : suggest(cur, fixed);
  }
  if (/^\d[\w.]*$/.test(cur)) {                          // Poetry: "1.2.3" = pin exacto
    return compareVersions(fixed, cur) > 0 ? { kind: 'edit', text: fixed } : { kind: 'none' };
  }
  return suggest(cur, fixed);
}
