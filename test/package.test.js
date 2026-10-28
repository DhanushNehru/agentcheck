import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// Test the tarball consumers install, not just files in the source checkout.
// --ignore-scripts prevents lifecycle recursion and any install-time scripts.
test('packed npm artifact includes a working CLI and changed-file scan modes', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentcheck-package-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  assert.ok(process.env.npm_execpath, 'Run this test through npm test');
  const npm = (...args) => execFileSync(process.execPath, [process.env.npm_execpath, ...args], {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
  const [packed] = JSON.parse(npm('pack', '--ignore-scripts', '--json', '--pack-destination', dir));
  assert.equal(packed.version, pkg.version);
  const names = new Set(packed.files.map((f) => f.path));
  for (const file of ['package.json', 'bin/agentcheck.js', 'src/git.js', 'src/scan.js',
    'src/rules.js', 'src/report.js', 'action.yml', 'README.md', 'LICENSE', 'CHANGELOG.md']) {
    assert.ok(names.has(file), `Missing from npm tarball: ${file}`);
  }
  assert.ok([...names].every((f) => !f.startsWith('test/') && !f.startsWith('.github/')));

  const prefix = path.join(dir, 'installed');
  npm('install', path.join(dir, packed.filename), '--prefix', prefix, '--offline',
    '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false');
  const installed = path.join(prefix, 'node_modules', ...pkg.name.split('/'));
  const manifest = JSON.parse(fs.readFileSync(path.join(installed, 'package.json'), 'utf8'));
  assert.equal(manifest.version, pkg.version);
  assert.equal(Object.keys(manifest.dependencies || {}).length, 0);
  const cli = path.join(installed, manifest.bin.agentcheck);
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(repo);
  const git = (...args) => execFileSync('git', ['-c', 'user.name=test',
    '-c', 'user.email=test@example.invalid', ...args], { cwd: repo, stdio: 'pipe' });
  const run = (...args) => spawnSync(process.execPath, [cli, ...args], { cwd: repo, encoding: 'utf8' });
  const json = (...args) => {
    const result = run(...args, '--format', 'json');
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return JSON.parse(result.stdout);
  };
  assert.equal(run('--version').stdout.trim(), pkg.version);
  assert.match(run('--help').stdout, /--diff <ref>/);
  assert.match(run('--help').stdout, /--staged/);
  git('init', '-q');
  fs.writeFileSync(path.join(repo, 'CLAUDE.md'), '# Rules\nUse clear names.\n');
  git('add', '.');
  git('commit', '-q', '-m', 'base');
  assert.equal(json('.', '--diff', 'HEAD').filesScanned, 0);
  fs.writeFileSync(path.join(repo, 'AGENTS.md'), '# Rules\nKeep changes small.\n');
  git('add', 'AGENTS.md');
  assert.equal(json('.', '--diff', 'HEAD').filesScanned, 1);
  assert.equal(json('.', '--staged').filesScanned, 1);
  const sarif = run('.', '--staged', '--format', 'sarif');
  assert.equal(sarif.status, 0, sarif.stderr);
  const report = JSON.parse(sarif.stdout);
  assert.equal(report.version, '2.1.0');
  assert.equal(report.runs[0].tool.driver.version, pkg.version);
  fs.writeFileSync(path.join(repo, 'AGENTS.md'), '# Rules\nHidden\u200btext\n');
  assert.equal(run('.', '--staged').status, 1);
  assert.equal(run('.', '--diff', 'HEAD').status, 1);
  assert.equal(run('.', '--staged', '--diff', 'HEAD').status, 2);
  assert.equal(run('.', '--diff', 'missing-release-ref').status, 2);
});
