#!/usr/bin/env node
// agentcheck - scan AI coding-agent config files for hidden prompt injection.
import fs from 'node:fs';
import { scanRepo } from '../src/scan.js';
import { toText, toJson, toSarif, failsThreshold } from '../src/report.js';
import { SEVERITY_ORDER } from '../src/rules.js';
import { changedSince, stagedFiles, GitError } from '../src/git.js';

const USAGE = `agentcheck - prompt-injection scanner for AI agent config files

Usage:
  agentcheck [path] [options]

Arguments:
  path                 Directory to scan (default: current directory)

Options:
  --format <fmt>       text | json | sarif   (default: text)
  --output <file>      Write the report to a file instead of stdout
  --fail-on <level>    low | medium | high | critical  (default: high)
                       Exit 1 when any finding is at least this severe
  --diff <ref>         Scan only files changed relative to a git ref or range,
                       e.g. origin/main or origin/main...HEAD (for PR scans in CI)
  --staged             Scan only files staged for the next commit (for pre-commit
                       hooks). Scans their working-tree content. Not with --diff
  --version           Print version
  --help               Show this help

What it scans: CLAUDE.md, AGENTS.md, GEMINI.md, .cursor/rules, .cursorrules,
.windsurf/rules, .clinerules, copilot-instructions.md, .roo/rules,
.amazonq/rules, .kiro/steering, MCP configs (.mcp.json, .cursor/mcp.json,
.vscode/mcp.json, ...), .claude/settings.json and similar files.
`;

function parseArgs(argv) {
  const opts = { path: '.', format: 'text', output: null, failOn: 'high', diff: null, staged: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return { help: true };
    if (a === '--version' || a === '-v') return { version: true };
    if (a === '--format') opts.format = argv[++i];
    else if (a.startsWith('--format=')) opts.format = a.slice(9);
    else if (a === '--output' || a === '-o') opts.output = argv[++i];
    else if (a.startsWith('--output=')) opts.output = a.slice(9);
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a.startsWith('--fail-on=')) opts.failOn = a.slice(10);
    else if (a === '--diff') opts.diff = argv[++i];
    else if (a.startsWith('--diff=')) opts.diff = a.slice(7);
    else if (a === '--staged') opts.staged = true;
    else if (a === '--sarif') opts.format = 'sarif';
    else if (a === '--json') opts.format = 'json';
    else if (!a.startsWith('-')) opts.path = a;
    else { console.error(`Unknown option: ${a}\n\n${USAGE}`); process.exit(2); }
  }
  return opts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  if (args.help) { console.log(USAGE); return; }
  if (args.version) { console.log(pkg.version); return; }

  if (!['text', 'json', 'sarif'].includes(args.format)) {
    console.error(`Unknown format: ${args.format}`); process.exit(2);
  }
  if (!SEVERITY_ORDER.includes(args.failOn)) {
    console.error(`Unknown --fail-on level: ${args.failOn}`); process.exit(2);
  }
  if (!fs.existsSync(args.path)) {
    console.error(`Path not found: ${args.path}`); process.exit(2);
  }

  if (args.staged && args.diff !== null) {
    console.error('Use either --staged or --diff, not both'); process.exit(2);
  }

  let only;
  if (args.staged || args.diff !== null) {
    try {
      only = args.staged ? stagedFiles(args.path) : changedSince(args.path, args.diff);
    } catch (err) {
      if (!(err instanceof GitError)) throw err;
      console.error(err.message); process.exit(2);
    }
  }

  const result = scanRepo(args.path, { only });
  let report;
  if (args.format === 'json') report = JSON.stringify(toJson(result), null, 2);
  else if (args.format === 'sarif') report = JSON.stringify(toSarif(result, pkg.version), null, 2);
  else report = toText(result, { diffRef: args.diff, staged: args.staged });

  if (args.output) {
    fs.writeFileSync(args.output, report + '\n');
    console.error(`Wrote ${args.format} report to ${args.output}`);
  } else {
    console.log(report);
  }

  const all = result.files.flatMap((f) => f.findings);
  process.exit(failsThreshold(all, args.failOn) ? 1 : 0);
}

main();
