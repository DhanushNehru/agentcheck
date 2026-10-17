import { RULE_METADATA, SEVERITY_ORDER } from './rules.js';

const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

export function worstSeverity(findings) {
  let worst = null;
  for (const f of findings) {
    if (!worst || SEVERITY_ORDER.indexOf(f.severity) > SEVERITY_ORDER.indexOf(worst)) worst = f.severity;
  }
  return worst;
}

export function failsThreshold(findings, failOn) {
  const min = SEVERITY_ORDER.indexOf(failOn);
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= min);
}

export function toJson(result) {
  return {
    tool: 'agentcheck',
    root: result.root,
    filesScanned: result.filesScanned,
    findings: result.files.flatMap((f) => f.findings.map((x) => ({ file: f.file, ...x }))),
  };
}

export function toText(result) {
  const lines = [];
  const all = result.files.flatMap((f) => f.findings.map((x) => ({ file: f.file, ...x })));
  const box = (s) => `│ ${s}`;
  lines.push('┌────────────────────────────────────────────────────┐');
  lines.push('│ 🕵️  agentcheck                                     │');
  lines.push('│ Prompt-injection scanner for AI agent config files │');
  lines.push('└────────────────────────────────────────────────────┘');
  lines.push('');

  if (result.filesScanned === 0) {
    lines.push('No AI agent config files found (looked for CLAUDE.md, AGENTS.md,');
    lines.push('.cursor/rules, .windsurf/rules, copilot-instructions.md, MCP configs, ...).');
    return lines.join('\n');
  }

  const groups = [
    ['critical', '🔴 CRITICAL'], ['high', '🟠 HIGH'],
    ['medium', '🟡 MEDIUM'], ['low', '🔵 LOW'],
  ];
  for (const [sev, title] of groups) {
    const hits = all.filter((f) => f.severity === sev);
    if (!hits.length) continue;
    lines.push(`  ${title}`);
    lines.push('  ' + '─'.repeat(52));
    for (const h of hits) {
      lines.push(`  ${ICON[sev]} ${h.file}:${h.line}:${h.col}  [${h.ruleId}]`);
      lines.push(`    ${h.message}`);
      lines.push('');
    }
  }

  const counts = Object.fromEntries(groups.map(([s]) => [s, all.filter((f) => f.severity === s).length]));
  lines.push('┌────────────────────────────────────────────────────┐');
  lines.push(box(`📄 ${result.filesScanned} agent config file(s) scanned`).padEnd(53) + '│');
  lines.push(box(`🔴 ${counts.critical} critical   🟠 ${counts.high} high   🟡 ${counts.medium} medium   🔵 ${counts.low} low`).padEnd(53) + '│');
  lines.push('└────────────────────────────────────────────────────┘');
  if (all.length === 0) {
    lines.push('');
    lines.push('No findings. Note: agentcheck is heuristic — a clean result does not');
    lines.push('prove a file is safe. Review rule changes like code changes.');
  } else {
    lines.push('');
    lines.push('Findings are heuristic and need human review; see README for limits.');
  }
  return lines.join('\n');
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };

export function toSarif(result, version = '0.1.0') {
  const all = result.files.flatMap((f) => f.findings.map((x) => ({ file: f.file, ...x })));
  const usedRules = [...new Set(all.map((f) => f.ruleId))];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'agentcheck',
          version,
          informationUri: 'https://github.com/DhanushNehru/agentcheck',
          rules: usedRules.map((id) => ({
            id,
            name: (RULE_METADATA[id] || {}).name || id,
            shortDescription: { text: (RULE_METADATA[id] || {}).name || id },
            defaultConfiguration: { level: SARIF_LEVEL[(RULE_METADATA[id] || {}).severity] || 'warning' },
          })),
        },
      },
      results: all.map((f) => ({
        ruleId: f.ruleId,
        level: SARIF_LEVEL[f.severity] || 'warning',
        message: { text: f.message },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: { startLine: f.line, startColumn: f.col },
          },
        }],
      })),
    }],
  };
}
