import path from 'node:path';
import { findTargets, readTarget, isJsonTarget } from './targets.js';
import { scanText } from './rules.js';

export function scanRepo(root) {
  const absRoot = path.resolve(root);
  const targets = findTargets(absRoot);
  const files = [];
  for (const rel of targets) {
    const text = readTarget(absRoot, rel);
    if (text == null) continue;
    const findings = scanText(text, { isJsonConfig: isJsonTarget(rel) });
    files.push({ file: rel, findings });
  }
  return { root: absRoot, filesScanned: files.length, files };
}

export function allFindings(result) {
  return result.files.flatMap((f) => f.findings.map((x) => ({ file: f.file, ...x })));
}
