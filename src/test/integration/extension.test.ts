// Pruebas dentro de VS Code (perfil aislado, vía @vscode/test-cli). La red se inyecta:
// nunca se consulta GitHub de verdad.
import * as assert from 'assert';
import * as vscode from 'vscode';

const ID = 'FelixAndresGonzalezOrtiz.vulnsync';

const resp = (status: number, body: any = []) => ({
  ok: status >= 200 && status < 300, status,
  headers: { get: () => null }, json: async () => body, text: async () => 'err',
});

suite('VulnSync (integración)', () => {
  let api: any;

  suiteSetup(async () => {
    const ext = vscode.extensions.getExtension(ID);
    assert.ok(ext, 'la extensión debe estar instalada');
    api = await ext!.activate();
    assert.ok(api?.setFetch, 'en modo de pruebas la extensión expone su API mínima');
  });

  test('registra todos los comandos declarados', async () => {
    const all = await vscode.commands.getCommands(true);
    const declared = vscode.extensions.getExtension(ID)!.packageJSON.contributes.commands.map((c: any) => c.command);
    for (const c of declared) assert.ok(all.includes(c), `falta el comando ${c}`);
  });

  test('GitHub caído → el escaneo queda incompleto, nunca "limpio"', async () => {
    api.setFetch(async () => resp(500));
    const r = await api.scan();
    assert.strictEqual(r.complete, false);
    assert.strictEqual(r.checkedDependencies, 0);
    const st = api.getState();
    assert.ok(!st.status.includes('$(pass)'), st.status);
  });

  test('GitHub ok sin avisos → completo', async () => {
    api.setFetch(async () => resp(200, []));
    const r = await api.scan();
    assert.strictEqual(r.complete, true);
    assert.ok(api.getState().status.includes('$(pass)'));
  });

  test('un aviso detectado genera un diagnóstico', async () => {
    api.setFetch(async () => resp(200, [{
      ghsa_id: 'GHSA-test-test-test', cve_id: null, html_url: 'https://github.com/advisories/GHSA-test-test-test',
      summary: 'prueba', severity: 'high', withdrawn_at: null,
      vulnerabilities: [{ package: { ecosystem: 'npm', name: 'left-pad' }, vulnerable_version_range: '< 2.0.0', first_patched_version: '2.0.0' }],
    }]));
    const r = await api.scan();
    assert.strictEqual(r.findings.length, 1);
    assert.strictEqual(api.diagnosticCount(), 1);
  });

  test('borrar la caché limpia resultados y diagnósticos', async () => {
    await vscode.commands.executeCommand('vulnsync.clearCache');
    assert.strictEqual(api.getState().result, undefined);
    assert.strictEqual(api.diagnosticCount(), 0);
  });
});
