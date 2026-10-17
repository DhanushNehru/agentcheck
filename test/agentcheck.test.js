import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanText, SEVERITY_ORDER } from '../src/rules.js';
import { scanRepo } from '../src/scan.js';
import { toSarif, toJson, failsThreshold } from '../src/report.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const mal = (n) => fs.readFileSync(path.join(here, 'fixtures/malicious', n), 'utf8');
const ben = (n) => fs.readFileSync(path.join(here, 'fixtures/benign', n), 'utf8');
const ids = (findings) => findings.map((f) => f.ruleId);

test('detects Unicode Tag smuggling and decodes the hidden payload', () => {
  const f = scanText(mal('unicode-tags.md'));
  const hit = f.find((x) => x.ruleId === 'unicode-tag-chars');
  assert.ok(hit, 'expected unicode-tag-chars finding');
  assert.equal(hit.severity, 'critical');
  assert.match(hit.message, /Decodes to:/);
  assert.match(hit.message, /previous instructions/i);
});

test('detects zero-width character clusters', () => {
  const f = scanText(mal('zero-width.md'));
  assert.ok(ids(f).includes('invisible-characters'));
});

test('detects instruction-override phrases', () => {
  const f = scanText(mal('override-phrase.md'));
  assert.ok(ids(f).includes('prompt-injection-phrase'));
});

test('detects AI-targeted instructions hidden in HTML comments', () => {
  const f = scanText(mal('html-comment.md'));
  assert.ok(ids(f).includes('hidden-comment-instructions'));
});

test('detects .env exfiltration to a request-capture endpoint', () => {
  const f = scanText(mal('exfil-env.md'));
  const hit = f.find((x) => x.ruleId === 'exfiltration-endpoint');
  assert.ok(hit, 'expected exfiltration-endpoint');
  assert.equal(hit.severity, 'critical');
});

test('detects curl-pipe-to-shell', () => {
  const f = scanText(mal('pipe-shell.md'));
  assert.ok(ids(f).includes('dangerous-command'));
});

test('detects bidi override characters', () => {
  const f = scanText(mal('bidi.md'));
  assert.ok(ids(f).includes('bidi-override'));
});

test('MCP config: flags plaintext secrets, auto-approve, remote server', () => {
  const f = scanText(mal('mcp-secret.json'), { isJsonConfig: true });
  const got = ids(f);
  assert.ok(got.includes('mcp-plaintext-secret'));
  assert.ok(got.includes('mcp-auto-approve'));
  assert.ok(got.includes('mcp-remote-server'));
});

test('benign style rules produce no findings', () => {
  const f = scanText(ben('style-rules.md'));
  assert.deepEqual(f, []);
});

test('benign MCP config with placeholder secret produces no findings', () => {
  const f = scanText(ben('mcp-safe.json'), { isJsonConfig: true });
  assert.deepEqual(f, []);
});

test('localhost curl usage produces no exfiltration finding', () => {
  const f = scanText(ben('curl-localhost.md'));
  assert.equal(f.filter((x) => x.ruleId === 'exfiltration-endpoint').length, 0);
});

test('scanRepo finds fixtures and reports per-file', () => {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'agentcheck-'));
  fs.mkdirSync(path.join(tmp, '.cursor/rules'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'CLAUDE.md'), mal('override-phrase.md'));
  fs.writeFileSync(path.join(tmp, '.cursor/rules/style.md'), ben('style-rules.md'));
  fs.writeFileSync(path.join(tmp, '.mcp.json'), mal('mcp-secret.json'));
  const r = scanRepo(tmp);
  assert.equal(r.filesScanned, 3);
  const all = r.files.flatMap((f) => f.findings);
  assert.ok(all.length >= 3);
});

test('SARIF output is structurally valid', () => {
  const r = scanRepo(here); // scans the repo; only fixtures match target names
  const sarif = toSarif(r, '0.1.0');
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].tool.driver.name === 'agentcheck');
  for (const res of sarif.runs[0].results) {
    assert.ok(res.ruleId && res.level && res.message.text);
    assert.ok(res.locations[0].physicalLocation.artifactLocation.uri);
    assert.ok(res.locations[0].physicalLocation.region.startLine >= 1);
  }
});

test('fail-on threshold honours severity order', () => {
  const f = scanText(mal('pipe-shell.md')); // medium finding
  assert.equal(failsThreshold(f, 'medium'), true);
  assert.equal(failsThreshold(f, 'high'), false);
  assert.deepEqual(SEVERITY_ORDER, ['low', 'medium', 'high', 'critical']);
});

test('toJson shape', () => {
  const r = scanRepo(here);
  const j = toJson(r);
  assert.equal(j.tool, 'agentcheck');
  assert.ok(Array.isArray(j.findings));
});
