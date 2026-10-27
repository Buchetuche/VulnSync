// Tipos compartidos. Este módulo (y todo src/core) no depende de 'vscode'
// para que se pueda probar con node --test.

export type Ecosystem = 'nuget' | 'npm' | 'pip';
export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export const SEVERITY_RANK: Record<Severity, number> = {
  unknown: 0, low: 1, medium: 2, high: 3, critical: 4,
};

/** Posición del texto de la versión dentro del manifiesto (0-based). */
export interface SourceLocation {
  file: string;          // ruta absoluta
  line: number;
  startCol: number;
  endCol: number;
}

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /** Versión exacta resuelta, si se conoce (lockfile o pin). */
  version?: string;
  /** Rango declarado tal cual (p. ej. "^4.17.0", ">=2.0"). */
  declared?: string;
  /** true si la versión se dedujo del rango (no hay lockfile). */
  approximate?: boolean;
  direct: boolean;
  location: SourceLocation;
}

/** Runtimes/SDK de Microsoft relevantes para los boletines MSRC. */
export interface RuntimeTarget {
  /** ".NET" o "ASP.NET Core" */
  product: '.NET' | 'ASP.NET Core';
  /** Banda major.minor, p. ej. "8.0" */
  band: string;
  /** Versión instalada/fijada si se conoce (p. ej. "8.0.10"). */
  version?: string;
  source: string;        // explicación de dónde salió
  location: SourceLocation;
}

export interface ProjectStack {
  ecosystems: Ecosystem[];
  dependencies: Dependency[];
  runtimes: RuntimeTarget[];
  manifests: string[];
}

export interface Finding {
  id: string;             // GHSA-… o CVE-…
  aliases: string[];
  source: 'github' | 'msrc';
  severity: Severity;
  cvss?: number;
  title: string;
  url: string;
  packageName: string;
  ecosystem: Ecosystem | 'runtime';
  installedVersion?: string;
  vulnerableRange?: string;
  fixedVersion?: string;
  /** true cuando no hay versión exacta y el hallazgo es probable, no seguro. */
  uncertain: boolean;
  location: SourceLocation;
  direct: boolean;
}
