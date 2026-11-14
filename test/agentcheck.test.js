import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanText, SEVERITY_ORDER } from '../src/rules.js';
import { scanRepo } from '../src/scan.js';
import { toSarif, toJson, toText, failsThreshold } from '../src/report.js';

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

test('detects hardcoded credentials in instruction files', () => {
  const f = scanText(mal('hardcoded-secrets.md'));
  const hits = f.filter((x) => x.ruleId === 'hardcoded-secret');
  assert.equal(hits.length, 3);
  assert.ok(hits.every((h) => h.severity === 'critical'));
  assert.match(hits[0].message, /Anthropic API key/);
  // findings must redact the credential, not echo it
  assert.ok(!hits[0].message.includes('sk-ant-api03-k9Xv2mPqR7sT4wY8zB1nL5dF'));
  assert.match(hits[0].message, /sk-a…/);
});

test('placeholder tokens and security guidance produce no findings', () => {
  const f = scanText(ben('secret-placeholders.md'));
  assert.deepEqual(f, []);
});

test('AWS documentation example key IDs are treated as placeholders', () => {
  const f = scanText('aws docs use AKIAIOSFODNN7EXAMPLE in examples');
  assert.equal(f.filter((x) => x.ruleId === 'hardcoded-secret').length, 0);
});

test('real-shaped AWS access key IDs are flagged', () => {
  const f = scanText('key id AKIAIOSFODNN7XAMPLE1');
  assert.equal(f.filter((x) => x.ruleId === 'hardcoded-secret').length, 1);
});

test('quoted line content is redacted in every report format', () => {
  const token = 'ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW';
  const f = scanText(mal('secret-in-quoted-line.md'));
  assert.ok(f.some((x) => x.ruleId === 'exfiltration-endpoint'), 'expected the exfil rule to fire');
  assert.ok(f.some((x) => x.ruleId === 'hardcoded-secret'), 'expected the secret rule to fire');
  for (const x of f) assert.ok(!x.message.includes(token), `raw token leaked in ${x.ruleId} message`);

  const tmp = fs.mkdtempSync(path.join(fs.realpathSync('/tmp'), 'agentcheck-redact-'));
  fs.writeFileSync(path.join(tmp, 'CLAUDE.md'), mal('secret-in-quoted-line.md'));
  const r = scanRepo(tmp);
  const text = toText(r);
  const json = JSON.stringify(toJson(r));
  const sarif = JSON.stringify(toSarif(r, '0.2.0'));
  for (const [name, out] of [['text', text], ['json', json], ['sarif', sarif]]) {
    assert.ok(!out.includes(token), `raw token leaked in ${name} report`);
  }
});
