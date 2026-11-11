#!/usr/bin/env bash
# Phase 2 — lightweight tracked-file secret/webshell scan.
# Scans git-tracked files only; exits 1 on any match.
set -euo pipefail

failed=0
report() { echo "SECURE-SCAN: $1 :: $2"; failed=1; }

while IFS= read -r -d '' file; do
  ext="${file##*.}"
  case "$ext" in
    png|jpg|jpeg|gif|webp|ico|svg|woff|woff2|ttf|otf|jar|jks|keystore|zip|gz|mp4|pdf|bin|lock|sum|so|gradle) continue;;
  esac
  case "$file" in
    node_modules/*|vendor/*|.git/*|.dart_tool/*|build/*|coverage/*) continue;;
  esac
  [[ -f "$file" ]] || continue
  # Skip files larger than 1 MB
  size=$(wc -c < "$file" | tr -d ' ')
  if (( size > 1048576 )); then continue; fi
  if grep -nEI 'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY' "$file" > /dev/null; then report "private-key-block" "$file"; fi
  if grep -nEI '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b' "$file" > /dev/null; then report "github-token" "$file"; fi
  if grep -nEI '\bxox[baprs]-[A-Za-z0-9-]{10,}\b' "$file" > /dev/null; then report "slack-token" "$file"; fi
  if grep -nEI '\bAKIA[0-9A-Z]{16}\b' "$file" > /dev/null; then report "aws-key" "$file"; fi
  if grep -nEI '\bsk_live_[A-Za-z0-9]{16,}\b' "$file" > /dev/null; then report "stripe-live-secret" "$file"; fi
  if grep -nEI '\bsk_test_[A-Za-z0-9]{24,}\b' "$file" > /dev/null; then report "stripe-test-secret" "$file"; fi
  # Google API keys other than the two public Firebase client keys shipped by design
  # (web client key + android client key for the same public Firebase project).
  if grep -noEI 'AIzaSy[A-Za-z0-9_-]{33}' "$file" | grep -vE 'AIzaSyCwH0a0pbRT2hqu_z-BHlJLzqYOUaDR4zM|AIzaSyCk-izCfnQbJvzteb2Uw8twDAylfe0m2JI' > /dev/null; then report "unrecognized-google-key" "$file"; fi
  # Webshell signature: request input piped into process/eval
  if grep -nEzi '(shell_exec|exec|system|passthru|popen|proc_open)\s*\(.{0,300}(\$_GET|\$_POST|\$_REQUEST|php://input)' "$file" > /dev/null; then report "webshell-signature" "$file"; fi
  if grep -nEzi 'eval\s*\(.{0,200}(\$_GET|\$_POST|\$_REQUEST)' "$file" > /dev/null; then report "eval-webshell" "$file"; fi
done < <(git ls-files -z)

if [ "$failed" -ne 0 ]; then
  echo "security-scan: FAILED — committed secrets or backdoors found (see above)" >&2
  exit 1
fi
echo "security-scan: OK"
