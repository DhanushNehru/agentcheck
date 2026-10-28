# Changelog

## 0.2.0 (unreleased)

### Added

- `--diff <ref>` scans agent config files changed relative to a git ref or range, including `origin/main...HEAD` (#12, @munirahmad9959).
- `--staged` scans agent config files staged for the next commit (#13, @munirahmad9959).
- The GitHub Action accepts a `diff` input. Check out full history (`fetch-depth: 0`) so the base ref is available.
- Packed-package smoke test checks the installed CLI, version, JSON/SARIF output and both new scan modes. `prepublishOnly` runs the test suite before an npm publish.

### Behavior and limits

- Both modes select changed file paths but scan their current working-tree content. `--staged` does not scan the exact index blob.
- Deleted files are skipped. No relevant files means exit `0`; findings at or above `--fail-on` mean exit `1`; invalid refs or use outside a git repository mean exit `2`.
- `--diff` and `--staged` cannot be combined. These modes do not compare before/after findings or distinguish new findings from existing ones.
- This prepares the next npm version; it does not publish the package or create a GitHub release or tag.

## 0.1.0

Initial npm release: heuristic scanning for agent instruction files and MCP configs, text/JSON/SARIF reports and a GitHub Action. No `--diff` or `--staged` CLI options in the published package.
