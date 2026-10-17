// Detection rules for hidden prompt-injection in AI-agent configuration files.
// Every rule is heuristic: it flags patterns documented in public research,
// and every match needs human review. See README "What it can't catch".

export const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

function lineCol(text, index) {
  const before = text.slice(0, index);
  const line = before.split('\n').length;
  const col = index - before.lastIndexOf('\n');
  return { line, col };
}

function finding(ruleId, severity, text, index, message) {
  const { line, col } = lineCol(text, index);
  return { ruleId, severity, line, col, message };
}

// Unicode "Tags" block: U+E0000..U+E007F map 1:1 to ASCII and render
// invisible in editors, but LLM tokenizers process them. Documented by
// Embrace The Red (2024); found in shared cursor rules by AgentSeal (2026).
function unicodeTags(text) {
  const re = /[\u{E0000}-\u{E007F}]/gu;
  const out = [];
  let m;
  while ((m = re.exec(text))) {
    let end = m.index;
    let decoded = '';
    while (end < text.length) {
      const cp = text.codePointAt(end);
      if (cp < 0xe0000 || cp > 0xe007f) break;
      const low = cp & 0x7f;
      decoded += low >= 0x20 && low < 0x7f ? String.fromCharCode(low) : ' ';
      end += cp > 0xffff ? 2 : 1;
    }
    out.push(finding('unicode-tag-chars', 'critical', text, m.index,
      `Invisible Unicode Tag characters (U+E0000 block) hide text that AI models still read. Decodes to: "${decoded.trim().slice(0, 120)}"`));
    re.lastIndex = end;
  }
  return out;
}

const INVISIBLE = {
  0x200b: 'zero-width space', 0x200c: 'zero-width non-joiner',
  0x200d: 'zero-width joiner', 0x2060: 'word joiner',
  0x00ad: 'soft hyphen', 0x180e: 'mongolian vowel separator',
  0x2061: 'function application', 0x2062: 'invisible times',
  0x2063: 'invisible separator', 0x2064: 'invisible plus',
  0xfeff: 'byte order mark',
};

function invisibleChars(text) {
  const hits = [];
  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i);
    if (cp > 0xffff) i++;
    if (cp === 0xfeff && i === 0) continue; // legit BOM at file start
    if (INVISIBLE[cp]) hits.push({ i, cp });
  }
  if (!hits.length) return [];
  const names = [...new Set(hits.map((h) => `${INVISIBLE[h.cp]} (U+${h.cp.toString(16).toUpperCase().padStart(4, '0')})`))];
  return [finding('invisible-characters', 'high', text, hits[0].i,
    `${hits.length} invisible character(s) found: ${names.join(', ')}. They render as nothing in editors but are tokenized by AI models, and are used to break up keywords or hide instructions.`)];
}

const BIDI = {
  0x202a: 'LRE', 0x202b: 'RLE', 0x202c: 'PDF', 0x202d: 'LRO', 0x202e: 'RLO',
  0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI',
  0x200e: 'LRM', 0x200f: 'RLM',
};

function bidiOverrides(text) {
  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i);
    if (BIDI[cp]) {
      return [finding('bidi-override', 'high', text, i,
        `Bidirectional text control ${BIDI[cp]} (U+${cp.toString(16).toUpperCase()}) can make text render in a different order than it is stored, hiding content from reviewers (Trojan Source class attack).`)];
    }
  }
  return [];
}

const INJECTION_PHRASES = [
  /ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|guidelines?|prompts?|messages?)/i,
  /disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?)/i,
  /forget\s+(all\s+|everything\s+)?(your\s+|you\s+)?(previous\s+|prior\s+)?instructions?/i,
  /do\s+not\s+(tell|inform|show|reveal|disclose\s+to)\s+the\s+(user|developer|human)/i,
  /never\s+(tell|inform|mention\s+to|reveal\s+to|show)\s+the\s+(user|developer|human)/i,
  /override\s+(your\s+|all\s+|any\s+)?(previous\s+|prior\s+)?(instructions?|rules?|guidelines?|safety)/i,
  /new\s+(system\s+)?instructions?\s*:/i,
  /you\s+are\s+now\s+(a|an|the)\s/i,
  /(pretend|act)\s+(to\s+be|as\s+if\s+you\s+(are|were))\s/i,
  /<(system|SYSTEM)>/,
];

function injectionPhrases(text) {
  const out = [];
  for (const re of INJECTION_PHRASES) {
    const m = re.exec(text);
    if (m) {
      out.push(finding('prompt-injection-phrase', 'high', text, m.index,
        `Phrase commonly used to override an AI assistant's instructions: "${m[0].slice(0, 100)}"`));
    }
  }
  return out;
}

// HTML comments are invisible when markdown is rendered. Instruction-like
// content inside them targets the AI reader, not the human one.
function hiddenCommentInstructions(text) {
  const out = [];
  const re = /<!--([\s\S]*?)-->/g;
  const aiWords = /\b(ai|assistant|model|llm|claude|copilot|cursor|windsurf|agent|gpt|gemini|codeium)\b/i;
  const instructive = /\b(ignore|always|never|must|follow|execute|run|do not|don't|send|fetch|include|read|output|reveal|bypass|disable)\b/i;
  let m;
  while ((m = re.exec(text))) {
    const body = m[1];
    if (body.length > 12 && aiWords.test(body) && instructive.test(body)) {
      out.push(finding('hidden-comment-instructions', 'high', text, m.index,
        `HTML comment (invisible when rendered) contains what looks like instructions to an AI assistant: "${body.trim().slice(0, 120)}"`));
    }
  }
  return out;
}

const EXFIL_HOSTS = /(^|[^a-zA-Z])(webhook\.site|requestbin|pipedream|ngrok\.io|beeceptor|oast\.|interactsh|burpcollaborator|canarytokens|hookbin)/i;
const NETWORK_TOOL = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc\s+-|netcat|fetch\()/i;
const SECRET_WORDS = /(\.env\b|api[_-]?key|secret|token|password|credential|ssh|id_rsa|\.aws\/credentials|\.npmrc|cookie|session)/i;

function exfiltration(text) {
  const out = [];
  const lines = text.split('\n');
  let offset = 0;
  for (const line of lines) {
    const idx = offset;
    offset += line.length + 1;
    const hm = EXFIL_HOSTS.exec(line);
    if (hm) {
      const sev = SECRET_WORDS.test(line) ? 'critical' : 'high';
      out.push(finding('exfiltration-endpoint', sev, text, idx + hm.index,
        `References a request-capture / tunneling service often used for data exfiltration: "${line.trim().slice(0, 120)}"`));
      continue;
    }
    if (NETWORK_TOOL.test(line) && /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(line) && SECRET_WORDS.test(line)) {
      out.push(finding('exfiltration-endpoint', 'critical', text, idx,
        `Combines a network tool with a reference to secrets or credentials: "${line.trim().slice(0, 120)}"`));
    }
  }
  return out;
}

const DANGEROUS = [
  { re: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*(\s|$)|--force)/, sev: 'high', label: 'force-deletes files (rm -f)' },
  { re: /chmod\s+(-R\s+)?777/, sev: 'medium', label: 'sets world-writable permissions (chmod 777)' },
  { re: /(curl|wget)[^|\n]{0,200}https?:\/\/[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh/, sev: 'medium', label: 'pipes a downloaded script straight into a shell' },
  { re: /\b(base64|openssl\s+enc)\s+(-[a-zA-Z]+\s+)*-?d(ecode)?\b[^|\n]*\|\s*(ba|z)?sh/, sev: 'high', label: 'decodes base64 into a shell' },
  { re: /\b(nc|ncat|netcat)\s+[^|\n]*-e\s/, sev: 'high', label: 'binds a shell to netcat (reverse shell pattern)' },
  { re: /\/dev\/tcp\//, sev: 'high', label: 'uses bash /dev/tcp (reverse shell / exfil pattern)' },
  { re: /\beval\s+["'`$]/, sev: 'medium', label: 'evaluates a string as code' },
];

function dangerousCommands(text) {
  const out = [];
  for (const { re, sev, label } of DANGEROUS) {
    const m = re.exec(text);
    if (m) out.push(finding('dangerous-command', sev, text, m.index, `Instructs the agent to run a command that ${label}: "${m[0].slice(0, 100)}"`));
  }
  return out;
}

const SENSITIVE_FILES = /(\.env\b|~\/\.ssh|id_rsa|\.aws\/credentials|\.npmrc|\/etc\/passwd|keychain|\.netrc|\.pgpass)/i;
const SEND_WORDS = /\b(send|upload|post|exfiltrate|transmit|email|attach|leak|print\s+the\s+contents|include\s+(the\s+)?(contents|full\s+contents))\b/i;
const NEGATION = /\b(never|don't|do not|must not|avoid|not to)\b/i;

function sensitiveFileAccess(text) {
  const out = [];
  const lines = text.split('\n');
  let offset = 0;
  for (const line of lines) {
    const idx = offset;
    offset += line.length + 1;
    const m = SENSITIVE_FILES.exec(line);
    if (!m) continue;
    if (SEND_WORDS.test(line) && !NEGATION.test(line)) {
      out.push(finding('sensitive-file-exfil', 'critical', text, idx + m.index,
        `Tells the agent to read a sensitive file AND send or include its contents somewhere: "${line.trim().slice(0, 120)}"`));
    }
    // Bare mentions ("never commit .env") are normal guidance and not flagged.
  }
  return out;
}

function base64Payload(text) {
  const out = [];
  const re = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])/g;
  let m;
  while ((m = re.exec(text))) {
    let decoded = '';
    try {
      decoded = Buffer.from(m[0], 'base64').toString('utf8');
    } catch { /* not decodable */ }
    const printable = /^[\x20-\x7e\s]*$/.test(decoded);
    const looksLikeInstructions = printable && INJECTION_PHRASES.some((r) => r.test(decoded));
    out.push(finding('base64-payload', looksLikeInstructions ? 'high' : 'medium', text, m.index,
      looksLikeInstructions
        ? `Base64 blob decodes to instruction-like text: "${decoded.trim().slice(0, 120)}"`
        : `Long base64 blob (${m[0].length} chars) in an instruction file; reviewers cannot see what it contains${printable ? `. Decodes to text starting: "${decoded.trim().slice(0, 80)}"` : ''}`));
  }
  return out;
}

// Cyrillic/Greek letters mixed into otherwise-Latin words (homoglyph spoofing).
function homoglyphMix(text) {
  const re = /\b(?=[A-Za-zЀ-ӿͰ-Ͽ]*[A-Za-z])(?=[A-Za-zЀ-ӿͰ-Ͽ]*[Ѐ-ӿͰ-Ͽ])[A-Za-zЀ-ӿͰ-Ͽ]{3,}\b/gu;
  const m = re.exec(text);
  if (m) {
    return [finding('homoglyph-mix', 'medium', text, m.index,
      `Word "${m[0]}" mixes Latin and Cyrillic/Greek letters; it looks like a normal word but is a different string (used to evade keyword filters).`)];
  }
  return [];
}

// --- MCP / JSON config rules -----------------------------------------------

function looksLikePlaceholder(value) {
  const s = String(value).trim();
  if (!s) return true;
  if (s.startsWith('$' + '{') || s.startsWith('{') || s.startsWith('%')) return true; // env interpolation
  return /^(your[-_ ]?|<[^>]*>|\[|xxx|example|sample|test|change|insert|replace|placeholder|todo)/i.test(s);
}

function looksLikeLiveSecret(key, value) {
  const s = String(value).trim();
  if (looksLikePlaceholder(s)) return false;
  const keyish = /(key|token|secret|password|passwd|auth)/i.test(key);
  if (/^AKIA[0-9A-Z]{16}$/.test(s)) return true; // AWS access key id
  if (/^[a-z][a-z0-9+.-]*:\/\/[^/\s:]+:[^@/\s]+@/i.test(s)) return true; // URL with embedded password
  if (/^(sk|pk|xox|ghp|gho|github_pat|hf|AIza|ya29)[-_A-Za-z0-9]{10,}$/.test(s)) return true; // common API token shapes
  return keyish && s.length >= 8;
}

// Walk parsed MCP-style config ({ mcpServers: { name: {...} } }).
function mcpConfigFindings(text, parsed) {
  const out = [];
  const servers = parsed && typeof parsed === 'object' ? parsed.mcpServers : null;
  if (!servers || typeof servers !== 'object') return out;

  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    const where = `MCP server "${name}"`;

    // 1. plaintext secrets committed into the config
    for (const [k, v] of Object.entries(cfg.env || {})) {
      if (typeof v === 'string' && looksLikeLiveSecret(k, v)) {
        const idx = text.indexOf(`"${k}"`);
        out.push(finding('mcp-plaintext-secret', 'high', text, idx >= 0 ? idx : 0,
          `${where} stores what looks like a live credential in env["${k}"]. Config files get committed and shared; use env-var references instead.`));
      }
    }

    // 2. command that fetches and runs code from a URL / git spec
    const args = Array.isArray(cfg.args) ? cfg.args.join(' ') : '';
    const cmd = `${cfg.command || ''} ${args}`;
    if (/(https?:\/\/|git@|github:|gitlab:|bitbucket:)/i.test(cmd)) {
      const idx = text.indexOf(`"${name}"`);
      out.push(finding('mcp-remote-code', 'high', text, idx >= 0 ? idx : 0,
        `${where} runs code fetched directly from a remote URL/git spec: "${cmd.trim().slice(0, 120)}". Verify the source is one you trust.`));
    }

    // 3. auto-approved tools: the agent runs them without asking
    const auto = cfg.autoApprove || cfg.alwaysAllow;
    if (Array.isArray(auto) && auto.length > 0) {
      const idx = text.indexOf(`"${name}"`);
      out.push(finding('mcp-auto-approve', 'medium', text, idx >= 0 ? idx : 0,
        `${where} auto-approves ${auto.length} tool(s) (${auto.slice(0, 5).join(', ')}): the agent can run them without asking the user. Review each one.`));
    }

    // 4. remote (URL-based) server
    if (typeof cfg.url === 'string' && /^https?:\/\//i.test(cfg.url)) {
      const idx = text.indexOf(cfg.url);
      out.push(finding('mcp-remote-server', 'low', text, idx >= 0 ? idx : 0,
        `${where} is a remote MCP server (${cfg.url}). Its tool descriptions are instructions the agent will follow; only use servers you trust.`));
    }
  }
  return out;
}

// --- registry ----------------------------------------------------------------

const TEXT_RULES = [
  unicodeTags, invisibleChars, bidiOverrides, injectionPhrases,
  hiddenCommentInstructions, exfiltration, dangerousCommands,
  sensitiveFileAccess, base64Payload, homoglyphMix,
];

export const RULE_METADATA = {
  'unicode-tag-chars': { name: 'Unicode Tag characters (invisible ASCII smuggling)', severity: 'critical' },
  'invisible-characters': { name: 'Invisible zero-width characters', severity: 'high' },
  'bidi-override': { name: 'Bidirectional text controls', severity: 'high' },
  'prompt-injection-phrase': { name: 'Prompt-injection phrase', severity: 'high' },
  'hidden-comment-instructions': { name: 'Instructions hidden in HTML comments', severity: 'high' },
  'exfiltration-endpoint': { name: 'Possible data exfiltration', severity: 'high' },
  'dangerous-command': { name: 'Dangerous shell command', severity: 'high' },
  'sensitive-file-exfil': { name: 'Sensitive file read + send', severity: 'critical' },
  'base64-payload': { name: 'Embedded base64 payload', severity: 'medium' },
  'homoglyph-mix': { name: 'Homoglyph character mix', severity: 'medium' },
  'mcp-plaintext-secret': { name: 'Plaintext secret in MCP config', severity: 'high' },
  'mcp-remote-code': { name: 'MCP server runs remote code', severity: 'high' },
  'mcp-auto-approve': { name: 'MCP tools auto-approved', severity: 'medium' },
  'mcp-remote-server': { name: 'Remote MCP server', severity: 'low' },
};

export function scanText(text, { isJsonConfig = false } = {}) {
  const findings = TEXT_RULES.flatMap((rule) => rule(text));
  if (isJsonConfig) {
    try {
      findings.push(...mcpConfigFindings(text, JSON.parse(text)));
    } catch {
      findings.push({ ruleId: 'json-parse-error', severity: 'low', line: 1, col: 1, message: 'File looks like a JSON agent config but does not parse as JSON.' });
    }
  }
  return findings.sort((a, b) => a.line - b.line || SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
}
