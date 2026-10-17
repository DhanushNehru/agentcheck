// Discovery of AI coding-agent configuration surfaces in a repository.
import fs from 'node:fs';
import path from 'node:path';

// File basenames that are agent instruction surfaces anywhere in the tree.
const BASENAMES = new Set([
  'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'GEMINI.md', 'QWEN.md',
  '.cursorrules', '.windsurfrules', '.clinerules', 'copilot-instructions.md',
]);

// Directories (relative to scan root) whose contents are instruction surfaces.
const RULE_DIRS = [
  '.cursor/rules', '.windsurf/rules', '.roo/rules', '.amazonq/rules',
  '.github/instructions', '.kiro/steering', '.augment/rules', '.claude/commands',
];

// Individual config files that deserve JSON-level MCP checks too.
const JSON_TARGETS = [
  '.mcp.json', 'mcp.json', '.cursor/mcp.json', '.vscode/mcp.json',
  '.claude/settings.json', '.claude/settings.local.json', '.gemini/settings.json',
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

export function isJsonTarget(relPath) {
  return JSON_TARGETS.includes(relPath) || /(^|\/)mcp[^/]*\.json$/i.test(relPath);
}

export function findTargets(root) {
  const found = [];
  const seen = new Set();

  const add = (abs) => {
    const rel = path.relative(root, abs).split(path.sep).join('/');
    if (seen.has(rel)) return;
    seen.add(rel);
    found.push(rel);
  };

  for (const rel of JSON_TARGETS) {
    const abs = path.join(root, rel);
    if (fs.existsSync(abs) && fs.statSync(abs).isFile()) add(abs);
  }

  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith('.git') && e.name !== '.github') {
        if (e.name === '.git') continue;
      }
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        walk(abs);
      } else if (e.isFile()) {
        const rel = path.relative(root, abs).split(path.sep).join('/');
        if (BASENAMES.has(e.name)) add(abs);
        else if (RULE_DIRS.some((d) => rel.startsWith(d + '/'))) add(abs);
      }
    }
  };
  walk(root);
  return found.sort();
}

export function readTarget(root, rel) {
  const abs = path.join(root, rel);
  const stat = fs.statSync(abs);
  if (stat.size > MAX_FILE_BYTES) return null;
  const buf = fs.readFileSync(abs);
  if (buf.includes(0)) return null; // binary
  return buf.toString('utf8');
}
