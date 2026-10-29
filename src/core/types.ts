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
  /** URI de la carpeta del workspace a la que pertenece el archivo (multiraíz). */
  workspace?: string;
}

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /**
   * Versión exacta resuelta, si se conoce (lockfile o pin). Cuando
   * `approximate` es true es solo el límite inferior del rango y NO es
   * evidencia de la versión instalada.
   */
  version?: string;
  /** Rango declarado tal cual (p. ej. "^4.17.0", ">=2.0"). */
  declared?: string;
  /** true si no hay versión exacta: solo se conoce el rango declarado. */
  approximate?: boolean;
  direct: boolean;
  location: SourceLocation;
}

/** SDK fijado en global.json. Es evidencia auxiliar: no equivale a un runtime. */
export interface SdkInfo {
  version: string;
  source: string;
  location: SourceLocation;
}

/** Runtimes de Microsoft relevantes para los boletines MSRC. */
export interface RuntimeTarget {
  /** ".NET" o "ASP.NET Core" */
  product: '.NET' | 'ASP.NET Core';
  /** Banda major.minor solicitada por el TFM, p. ej. "8.0" */
  band: string;
  /** Versión de runtime solicitada o fijada (RuntimeFrameworkVersion / runtimeconfig.json). */
  version?: string;
  /** Proyecto o aplicación que usa este runtime. */
  app: string;
  /** 'app' = ejecutable; 'library' = el runtime lo define quien la consume; 'implied' = deducido de un paquete. */
  appKind: 'app' | 'library' | 'implied';
  selfContained?: boolean;
  /** Política de roll-forward (Disable, LatestPatch, Minor, LatestMinor, Major, LatestMajor). */
  rollForward?: string;
  /** Evidencia con la que se obtuvo `version` (p. ej. "runtimeconfig.json"). */
  evidence: string;
  source: string;        // explicación de dónde salió
  location: SourceLocation;
}

export interface ProjectStack {
  ecosystems: Ecosystem[];
  dependencies: Dependency[];
  runtimes: RuntimeTarget[];
  /** SDK fijados (global.json), solo informativos. */
  sdks?: SdkInfo[];
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
  /** Rango declarado cuando la versión instalada no se conoce. */
  declaredRange?: string;
  vulnerableRange?: string;
  fixedVersion?: string;
  /** true cuando no hay versión exacta y el hallazgo es probable, no seguro. */
  uncertain: boolean;
  location: SourceLocation;
  direct: boolean;
  /** Aplicación que usa el runtime (solo hallazgos de runtime). */
  app?: string;
  /** Qué evidencia determinó la versión efectiva (solo runtime). */
  evidence?: string;
}

/** Estado de cada fuente de datos en un escaneo. */
export type SourceState = 'complete' | 'partial' | 'cached' | 'failed' | 'notApplicable';

export interface SourceStatus {
  source: 'github' | 'msrc';
  state: SourceState;
  /** Explicación legible (errores, documentos fallidos, antigüedad…). */
  detail?: string;
  /** Fecha de los datos usados (caché). */
  dataAsOf?: string;
}
