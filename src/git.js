// Thin git helpers for scanning only the files a change touches.
import { execFileSync } from 'node:child_process';

export class GitError extends Error {}

function git(cwd, args) {
  try {
    return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (err) {
    if (err.code === 'ENOENT') throw new GitError('git is not installed or not on PATH');
    const detail = String(err.stderr || err.message).trim().split('\n')[0];
    throw new GitError(detail);
  }
}

// Paths of added/copied/modified/renamed files reported by `git diff <diffArgs>`,
// relative to `dir` and using "/" separators. Deleted files are left out because
// there is nothing left to scan. `dir` may be a subdirectory of the repository;
// files outside it are not returned.
export function changedFiles(dir, diffArgs = []) {
  try {
    git(dir, ['rev-parse', '--is-inside-work-tree']);
  } catch {
    throw new GitError(`${dir} is not inside a git repository`);
  }
  const out = git(dir, ['diff', '--name-only', '-z', '--relative', '--diff-filter=ACMR', ...diffArgs, '--']);
  return new Set(out.split('\0').filter(Boolean));
}

// Files staged for the next commit (`git diff --cached`).
export function stagedFiles(dir) {
  return changedFiles(dir, ['--cached']);
}

// Files changed relative to a ref or range, e.g. "origin/main" or "origin/main...HEAD".
export function changedSince(dir, ref) {
  if (!ref || ref.startsWith('-')) throw new GitError(`--diff needs a git ref or range, got: ${ref ?? '(nothing)'}`);
  try {
    return changedFiles(dir, [ref]);
  } catch (err) {
    if (err.message.includes('not inside a git repository')) throw err;
    throw new GitError(`Cannot diff against "${ref}": ${err.message}`);
  }
}
