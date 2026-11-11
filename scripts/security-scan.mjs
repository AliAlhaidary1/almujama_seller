#!/usr/bin/env node
/**
 * Phase 2 — tracked-file secret/webshell scan.
 * Scans git-tracked files only; exits 1 on any match.
 * Runs in CI (ubuntu-latest) and locally via `node scripts/security-scan.mjs`.
 */
import { execSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';

const tracked = execSync('git ls-files -z', { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  .split('\0')
  .filter(Boolean);

const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.otf',
  '.jar', '.jks', '.keystore', '.zip', '.gz', '.mp4', '.pdf', '.bin', '.lock', '.so', '.gradle',
]);
const SKIP_PATH = /(^|\/)(node_modules|vendor|\.git|\.dart_tool|build|coverage|dist)\//;

// Public Firebase client keys are public by design (shipped inside the APK; useless
// without a restricted app/domain registration). Anything else Google-shaped is flagged.
const PUBLIC_GOOGLE_KEYS = new Set([
  'AIzaSyCwH0a0pbRT2hqu_z-BHlJLzqYOUaDR4zM', // Firebase web client config (public)
  'AIzaSyCk-izCfnQbJvzteb2Uw8twDAylfe0m2JI', // Firebase android client config (public)
]);
const GOOGLE_KEY_RE = /\bAIzaSy[A-Za-z0-9_-]{33}\b/g;

const SECRET_PATTERNS = [
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['GitHub personal token', /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/],
  ['Stripe live secret key', /\bsk_live_[A-Za-z0-9]{16,}\b/],
  ['Stripe test secret key', /\bsk_test_[A-Za-z0-9]{24,}\b/],
];
const WEBSHELL_RE = /(shell_exec|\bexec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\()[\s\S]{0,300}(\$_GET|\$_POST|\$_REQUEST|php:\/\/input)/i;
const EVAL_RE = /\beval\s*\([\s\S]{0,200}(\$_GET|\$_POST|\$_REQUEST)/i;

const findings = [];
for (const file of tracked) {
  if (/\.(png|jpg|jpeg|gif|webp|ico|svg|woff2?|ttf|otf|jar|jks|keystore|zip|gz|mp4|pdf|bin|so)$/i.test(file)) continue;
  if (SKIP_PATH.test(file)) continue;
  let contents = '';
  try {
    if (statSync(file).size > 1048576) continue;
    contents = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  for (const [label, pattern] of SECRET_PATTERNS) {
    if (pattern.test(contents)) findings.push(`${label} :: ${file}`);
  }
  for (const match of contents.matchAll(GOOGLE_KEY_RE)) {
    if (!PUBLIC_GOOGLE_KEYS.has(match[0])) findings.push(`Unrecognized Google API key :: ${file}`);
  }
  if (WEBSHELL_RE.test(contents)) findings.push(`Webshell signature :: ${file}`);
  if (EVAL_RE.test(contents)) findings.push(`Eval webshell signature :: ${file}`);
}

if (findings.length) {
  console.error('security-scan: FAILED');
  for (const f of findings) console.error(` - ${f}`);
  process.exit(1);
}
console.log(`security-scan: OK (${tracked.length} tracked files)`);
