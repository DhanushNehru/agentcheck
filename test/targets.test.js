import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { findTargets } from '../src/targets.js';
import { scanRepo } from '../src/scan.js';
import { toJson } from '../src/report.js';

function fixture(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentcheck-targets-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return dir;
}

test('findTargets discovers root and nested MCP filename variants, not unrelated JSON', (t) => {
  const dir = fixture(t, {
    'mcp-extra.json': '{}',
    'config/mcp.json': '{}',
    'config/MCP-Prod.JSON': '{}',
    'config/deep/mcp-extra.json': '{}',
    'config/notmcp.json': '{}',
    'config/mcp.json.bak': '{}',
    'package.json': '{}',
  });
  assert.deepEqual(findTargets(dir), [
    'config/MCP-Prod.JSON',
    'config/deep/mcp-extra.json',
    'config/mcp.json',
    'mcp-extra.json',
  ]);
});

test('findTargets keeps known JSON targets unique and skips excluded directories', (t) => {
  const dir = fixture(t, {
    '.mcp.json': '{}',
    '.cursor/mcp.json': '{}',
    '.claude/settings.json': '{}',
    'node_modules/pkg/mcp.json': '{}',
    'pkg/node_modules/mcp.json': '{}',
    '.git/mcp.json': '{}',
    'dist/mcp.json': '{}',
  });
  assert.deepEqual(findTargets(dir), [
    '.claude/settings.json',
    '.cursor/mcp.json',
    '.mcp.json',
  ]);
});

test('scanRepo reports nested MCP findings without treating other surfaces as JSON configs', (t) => {
  const config = JSON.stringify({
    mcpServers: { review: { url: 'https://example.invalid/mcp' } },
  });
  const dir = fixture(t, {
    'config/mcp.json': config,
    'config/settings.json': config,
    'CLAUDE.md': config,
  });
  const result = scanRepo(dir);
  assert.equal(result.filesScanned, 2);
  assert.deepEqual(result.files.map((f) => f.file), ['CLAUDE.md', 'config/mcp.json']);
  assert.deepEqual(toJson(result).findings.map((f) => ({ file: f.file, ruleId: f.ruleId })), [
    { file: 'config/mcp.json', ruleId: 'mcp-remote-server' },
  ]);
});
