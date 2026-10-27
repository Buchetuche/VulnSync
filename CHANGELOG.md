# Registro de cambios

## 0.1.0 — 2026-10-26

Primera versión preliminar.

- Detección del stack: .NET / NuGet, Node.js / npm y Python / PyPI, con soporte de lockfiles (`packages.lock.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`, `Pipfile.lock`) y Central Package Management.
- Sincronización de los boletines del Microsoft Security Response Center (API CVRF v3.0) para runtimes .NET y ASP.NET Core, con caché incremental.
- Consulta de la GitHub Advisory Database para paquetes NuGet, npm y PyPI.
- Diagnósticos en la línea exacta de la versión, acciones rápidas para actualizar, panel lateral, barra de estado y reporte en Markdown.
