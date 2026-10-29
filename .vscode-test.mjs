import { defineConfig } from '@vscode/test-cli';

export default defineConfig({
  files: 'out/test/integration/**/*.test.js',
  workspaceFolder: './test-fixtures/npm-ws',
  version: 'stable',
  launchArgs: ['--disable-extensions', '--user-data-dir=.vscode-test/user-data', '--extensions-dir=.vscode-test/extensions'],
  mocha: { ui: 'tdd', timeout: 60000 },
});
