# VulnSync — MSRC & GitHub Advisory para VS Code

Extensión que detecta el stack de tu proyecto, sincroniza los reportes de vulnerabilidades publicados por Microsoft y te marca en el editor qué dependencias o runtimes están afectados.

Funciona en VS Code y en editores basados en él (Cursor, Windsurf, VSCodium).

## Fuentes de datos

| Fuente | Qué cubre | Cómo se consulta |
|---|---|---|
| **MSRC – Security Update Guide** (API CVRF v3.0) | Runtimes y SDK de **.NET** y **ASP.NET Core** | `GET api.msrc.microsoft.com/cvrf/v3.0/updates` + documento mensual. Se descargan los últimos N meses (12 por defecto), se reducen a .NET/ASP.NET Core y se guardan en caché; las siguientes sincronizaciones solo bajan boletines nuevos o revisados. |
| **GitHub Advisory Database** (Microsoft/GitHub) | Paquetes de **NuGet**, **npm** y **PyPI** | `GET api.github.com/advisories?ecosystem=…&affects=pkg@versión`, en lotes de hasta 1000 paquetes. Cada rango vulnerable se vuelve a verificar localmente. |

No requiere claves de API. Si inicias sesión en GitHub desde VS Code (comando **VulnSync: Iniciar sesión en GitHub**), el límite sube de 60 a 5000 peticiones/hora; la sesión no pide permisos sobre tus repositorios.

## Detección del stack

| Stack | Manifiestos | Versiones exactas desde |
|---|---|---|
| .NET / NuGet | `*.csproj`, `*.fsproj`, `*.vbproj`, `Directory.Packages.props` (CPM), `Directory.Build.props`, `global.json` | `packages.lock.json`; runtimes vía `dotnet --list-runtimes` o `RuntimeFrameworkVersion` |
| Node.js / npm | `package.json` (incl. monorepos) | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 y Berry), `pnpm-lock.yaml` |
| Python / PyPI | `requirements*.txt`, `pyproject.toml` (PEP 621, `dependency-groups`, Poetry) | `poetry.lock`, `uv.lock`, `Pipfile.lock`, o pines `==` |

Sin lockfile, la versión se aproxima con el límite inferior del rango declarado (`^4.17.0` → `4.17.0`) y el hallazgo se muestra como **por confirmar**. Lo mismo ocurre con los boletines de .NET cuando `dotnet` no está en el PATH.

## En el editor

- **Diagnósticos** sobre la línea exacta de la versión en el manifiesto (error para crítica/alta, advertencia para media, información para baja o por confirmar), con el ID enlazado al boletín.
- **Acciones rápidas** (`Ctrl+.`): actualizar a la versión corregida conservando el prefijo del rango, descargar el runtime de .NET, abrir el boletín o ignorar el ID.
- **Panel VulnSync** en la barra de actividad: vulnerabilidades agrupadas por paquete y el stack detectado.
- **Barra de estado** con el conteo; roja si hay hallazgos críticos o altos.
- **Reporte Markdown** (`VulnSync: Generar reporte`) para adjuntar a un PR o ticket.
- Reescaneo automático al guardar un manifiesto o lockfile, y sincronización periódica.

## Configuración

| Ajuste | Por defecto | Descripción |
|---|---|---|
| `vulnsync.ecosystems` | `["nuget","npm","pip"]` | Ecosistemas analizados |
| `vulnsync.syncIntervalHours` | `12` | Frecuencia de sincronización y reescaneo |
| `vulnsync.msrc.enabled` | `true` | Consultar MSRC para runtimes .NET |
| `vulnsync.msrc.monthsToSync` | `12` | Boletines mensuales a mantener |
| `vulnsync.msrc.checkInstalledRuntimes` | `true` | Ejecutar `dotnet --list-runtimes` |
| `vulnsync.github.useVSCodeAuth` | `true` | Usar la sesión de GitHub de VS Code |
| `vulnsync.minimumSeverity` | `low` | Severidad mínima mostrada |
| `vulnsync.includeTransitive` | `true` | Analizar dependencias transitivas de los lockfiles |
| `vulnsync.exclude` | `node_modules`, `bin`, `obj`, `.venv`… | Globs excluidos |
| `vulnsync.ignoredAdvisories` | `[]` | IDs GHSA/CVE a omitir (se guarda en el workspace) |

## Desarrollo

```bash
npm install
npm run compile      # compila a out/
npm test             # pruebas unitarias del núcleo (node --test)
npm run package      # genera vulnsync-0.1.0.vsix
```

Pulsa **F5** en VS Code para abrir una ventana de desarrollo con la extensión cargada.

Instalar el `.vsix`: *Extensiones → … → Instalar desde VSIX*, o `code --install-extension vulnsync-0.1.0.vsix`.

### Estructura

```
src/
  core/                 # sin dependencia de 'vscode' (testeable)
    types.ts            # Dependency, RuntimeTarget, Finding
    version.ts          # comparación semver/NuGet/PEP 440 y rangos GHSA
    detect.ts           # combina manifiestos + lockfiles por directorio
    parsers/            # npm, yarn/pnpm, MSBuild/NuGet, Python
    sources/github.ts   # GitHub Advisory API + matching
    sources/msrc.ts     # MSRC CVRF v3.0, sync incremental + matching
    scan.ts             # orquestación, filtros, reporte Markdown
  ui/                   # diagnósticos, acciones rápidas, vistas
  extension.ts          # activación, comandos, watchers, caché
```

Para publicar en el Marketplace, sube el `.vsix` desde la página de gestión del Marketplace o ejecuta `npx @vscode/vsce publish`.

## Limitaciones conocidas

- Las propiedades MSBuild en versiones (`Version="$(MyVersion)"`) no se resuelven.
- MSRC solo se usa para .NET / ASP.NET Core; los paquetes NuGet de Microsoft (p. ej. `System.Text.Json`) se cubren por GitHub Advisory, donde Microsoft también publica sus avisos.
- Los runtimes autocontenidos (`SelfContained`) se evalúan con la versión fijada en `RuntimeFrameworkVersion` si existe.
