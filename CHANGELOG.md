# Registro de cambios

## 0.1.1 — 2026-10-27

Correcciones de la auditoría de 0.1.0 (VS-001 … VS-013).

**MSRC**
- Corregido: algunos boletines de MSRC indican la versión corregida del **SDK** de .NET (por ejemplo 8.0.427) en lugar de la del **runtime**. Antes se comparaba con el runtime instalado y producía avisos falsos ("actualiza a 8.0.427"); ahora se usa la versión de runtime cuando existe y, si MSRC solo publica la del SDK, el hallazgo se marca como "por confirmar" y muestra `SDK 8.0.427` como versión corregida.
- La caché de boletines MSRC ahora lleva versión de formato: la creada por 0.1.0 (con las versiones de SDK mezcladas) se descarta automáticamente al actualizar y se vuelve a descargar, sin que haga falta borrarla a mano.

**Seguridad y confiabilidad**
- VS-001: cada fuente (GitHub, MSRC) tiene estado `complete / partial / cached / failed / notApplicable`. Un escaneo incompleto se muestra como tal en la barra de estado, la notificación, el árbol y el reporte, y nunca en verde. Solo cuentan como verificadas las dependencias cuyos lotes terminaron bien.
- VS-002: sin lockfile se consulta por nombre y se compara la intersección del rango declarado con el vulnerable (SemVer, NuGet, PEP 440/Poetry). NuGet `1.2.3` sin lockfile ya no se trata como versión instalada.
- VS-003: en monorepos npm cada workspace recibe la versión que le corresponde por su ruta en `package-lock.json`, junto con sus transitivas (resolución estilo Node).
- VS-004: el token solo se envía a `https://api.github.com/advisories`; la paginación se reconstruye a partir del cursor y se rechaza cualquier otro origen. Se añade `X-GitHub-Api-Version` y `redirect: 'error'`.

**Precisión multistack**
- VS-005: `global.json` pasa a ser información del SDK (no un runtime). Los runtimes se asocian a su aplicación; se leen `RuntimeFrameworkVersion`, `SelfContained`, `RollForward` y `*.runtimeconfig.json`; los runtimes instalados son evidencia auxiliar y cada hallazgo indica aplicación y evidencia.
- VS-006: las acciones rápidas solo editan pines y rangos simples sin ampliarlos; el resto se muestra como sugerencia. Los cambios piden vista previa.
- VS-007: soporte de `Pipfile` (activación, watcher, directas/dev) junto con `Pipfile.lock`.
- VS-008: la caché MSRC registra el estado por documento, reintenta con backoff y se marca como parcial; `syncedAt` solo avanza si todo está al día.

**Publicación y mejoras menores**
- VS-009: `vscode:prepublish`, `@vscode/vsce` fijado, lockfile regenerado, CI con comprobación de árbol limpio y SHA-256 del VSIX.
- VS-010: pruebas de regresión y pruebas de integración en VS Code (`npm run test:integration`).
- VS-011: rutas relativas a su carpeta de workspace (multiraíz); VS-012: borrar la caché limpia también la interfaz; VS-013: todo contenido externo se escapa en Markdown.
- Workspace Trust: en workspaces no confiables no se ejecuta `dotnet --list-runtimes`.

## 0.1.0 — 2026-10-26

Primera versión preliminar.

- Detección del stack: .NET / NuGet, Node.js / npm y Python / PyPI, con soporte de lockfiles (`packages.lock.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`) y Central Package Management.
- Sincronización de los boletines del Microsoft Security Response Center (API CVRF v3.0) para runtimes .NET y ASP.NET Core, con caché incremental.
- Consulta de la GitHub Advisory Database para paquetes NuGet, npm y PyPI.
- Diagnósticos en la línea exacta de la versión, acciones rápidas para actualizar, panel lateral, barra de estado y reporte en Markdown.
