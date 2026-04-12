name: AI Security Remediation

on:
  push:
    branches: [ "main" ]
  workflow_dispatch:

jobs:
  security-remediation:
    runs-on: self-hosted
    env:
      GITHUB_TOKEN: ${{ secrets.PAT_TOKEN }}
      OLLAMA_MODEL: "gemma3:1b-it-qat"
      REPO: "Mukul9090/SAST-Code-Fix"

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Semgrep Scan
        run: |
          pip install semgrep 2>/dev/null || pip install semgrep --break-system-packages 2>/dev/null
          semgrep --config auto --json --output semgrep-results.json . || true
          echo "✔ Semgrep scan complete"

      - name: Start Ollama
        run: |
          pkill ollama 2>/dev/null || true
          sleep 2
          ollama serve &
          sleep 5
          ollama pull ${OLLAMA_MODEL}
          echo "✔ Model ready"

          echo "▸ Quick test:"
          ollama run ${OLLAMA_MODEL} "Say OK" --verbose 2>&1 | head -5
          echo ""

      - name: AI Remediation
        run: |
          set +e

          echo "════════════════════════════════════════════════"
          echo "  AI SECURITY REMEDIATION"
          echo "  Model: ${OLLAMA_MODEL}"
          echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
          echo "════════════════════════════════════════════════"
          echo ""

          if [ ! -f semgrep-results.json ]; then
            echo "▸ No scan results — skipping"
            exit 0
          fi

          # ── Deduplicate findings ─────────────────────────
          python3 << 'PYEOF'
          import json, os
          os.makedirs('/tmp/findings', exist_ok=True)
          with open('semgrep-results.json') as f:
              data = json.load(f)
          seen = set()
          count = 0
          for r in data.get('results', []):
              severity = r.get('extra', {}).get('severity', '').upper()
              if severity not in ('ERROR', 'WARNING'):
                  continue
              fp = r.get('path', '')
              sl = r.get('start', {}).get('line', 0)
              key = f"{fp}:{sl}"
              if key in seen:
                  continue
              seen.add(key)
              with open(f'/tmp/findings/f_{count}.meta', 'w') as m:
                  json.dump({
                      'file': fp,
                      'start': sl,
                      'end': r.get('end', {}).get('line', 0),
                      'rule': r.get('check_id', '').split('.')[-1],
                      'full_rule': r.get('check_id', ''),
                      'severity': severity,
                      'message': r.get('extra', {}).get('message', ''),
                      'lines': r.get('extra', {}).get('lines', '')
                  }, m)
              count += 1
          print(f"Deduplicated: {len(data.get('results', []))} → {count} unique findings")
          PYEOF

          FINDING_COUNT=$(ls /tmp/findings/f_*.meta 2>/dev/null | wc -l | tr -d ' ')
          echo "▸ Processing ${FINDING_COUNT} findings"
          echo ""

          if [ "$FINDING_COUNT" = "0" ]; then
            echo "✔ No findings to fix"
            exit 0
          fi

          git config user.name "AI Security Bot"
          git config user.email "security-bot@automated.fix"

          TOTAL=0
          FIXED=0
          FAILED=0
          FIX_PRS=""

          for META in /tmp/findings/f_*.meta; do
            [ -f "$META" ] || continue

            FILE=$(python3 -c "import json; print(json.load(open('$META'))['file'])")
            RULE=$(python3 -c "import json; print(json.load(open('$META'))['rule'])")
            SEVERITY=$(python3 -c "import json; print(json.load(open('$META'))['severity'])")
            LINES=$(python3 -c "import json; print(json.load(open('$META'))['lines'])")
            MSG=$(python3 -c "import json; print(json.load(open('$META'))['message'][:100])")

            TOTAL=$((TOTAL + 1))
            echo "  [${TOTAL}/${FINDING_COUNT}] ${SEVERITY} — ${RULE}"
            echo "       File: ${FILE}"
            echo "       Issue: ${MSG}"

            # ── Build prompt file ──────────────────────────
            python3 -c "
          import json
          meta = json.load(open('$META'))
          prompt = f\"\"\"Fix this {meta['rule']} security vulnerability.
          Return ONLY the fixed code. No explanation. No markdown fences.

          Vulnerable code:
          {meta['lines']}\"\"\"
          req = {
              'model': '${OLLAMA_MODEL}',
              'messages': [
                  {'role': 'system', 'content': 'You fix code vulnerabilities. Reply with ONLY the corrected code. No explanation. No markdown. No backticks.'},
                  {'role': 'user', 'content': prompt}
              ],
              'stream': False,
              'options': {'temperature': 0.1, 'num_ctx': 2048}
          }
          with open('/tmp/ollama_req.json', 'w') as f:
              json.dump(req, f)
          "

            # ── Call Ollama ────────────────────────────────
            RAW=$(curl -sS --max-time 60 \
              -X POST http://localhost:11434/api/chat \
              -H "Content-Type: application/json" \
              -d @/tmp/ollama_req.json 2>&1)

            # Extract content and strip markdown fences
            python3 -c "
          import sys, json
          try:
              data = json.loads(sys.argv[1])
              if 'error' in data:
                  print('ERROR: ' + data['error'], file=sys.stderr)
                  sys.exit(1)
              c = data.get('message', {}).get('content', '').strip()
              # Strip markdown fences
              lines = c.split('\n')
              clean = []
              for line in lines:
                  if line.strip().startswith('\`\`\`'):
                      continue
                  clean.append(line)
              result = '\n'.join(clean).strip()
              with open('/tmp/ai_fix.txt', 'w') as f:
                  f.write(result)
              print(result[:100])
          except Exception as e:
              print(f'PARSE ERROR: {e}', file=sys.stderr)
              sys.exit(1)
          " "$RAW" 2>/tmp/ai_error.txt

            if [ $? -ne 0 ] || [ ! -s /tmp/ai_fix.txt ]; then
              echo "       ✘ AI failed: $(cat /tmp/ai_error.txt 2>/dev/null)"
              FAILED=$((FAILED + 1))
              echo ""
              continue
            fi

            echo "       ✔ Fix received"

            # ── Create branch ──────────────────────────────
            BRANCH_NAME="fix/sast-${RULE}-$(echo $TOTAL | md5sum | head -c 6)"

            git checkout main 2>/dev/null
            git checkout -b "$BRANCH_NAME" 2>/dev/null

            # ── Apply fix ─────────────────────────────────
            export CURRENT_META="$META"
            python3 << 'PYEOF'
          import json, os

          with open(os.environ['CURRENT_META']) as f:
              m = json.load(f)

          with open('/tmp/ai_fix.txt') as f:
              fixed_code = f.read().strip()

          if not fixed_code:
              print("Empty fix")
              exit(1)

          with open(m['file']) as f:
              lines = f.readlines()

          start = m['start'] - 1
          end = m['end']

          if not fixed_code.endswith('\n'):
              fixed_code += '\n'

          new_lines = lines[:start] + [fixed_code] + lines[end:]

          with open(m['file'], 'w') as f:
              f.writelines(new_lines)

          print(f"Patched {m['file']} lines {m['start']}-{m['end']}")
          PYEOF

            if [ $? -ne 0 ]; then
              echo "       ⚠ Patch failed"
              git checkout main 2>/dev/null
              FAILED=$((FAILED + 1))
              echo ""
              continue
            fi

            # ── Check for actual changes ───────────────────
            if git diff --quiet; then
              echo "       ⚠ No diff — skipping"
              git checkout main 2>/dev/null
              echo ""
              continue
            fi

            # ── Commit and push ────────────────────────────
            git add "$FILE"
            git commit -m "fix: resolve ${RULE} in ${FILE}

          Severity: ${SEVERITY}
          Auto-generated by ${OLLAMA_MODEL}" 2>/dev/null

            git push "https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git" "$BRANCH_NAME" --force 2>/dev/null

            if [ $? -ne 0 ]; then
              echo "       ⚠ Push failed — check PAT_TOKEN permissions"
              git checkout main 2>/dev/null
              FAILED=$((FAILED + 1))
              echo ""
              continue
            fi

            echo "       ✔ Pushed branch: ${BRANCH_NAME}"

            # ── Create PR ──────────────────────────────────
            python3 -c "
          import json
          pr = {
              'title': '🔒 AI Fix: $RULE in $FILE',
              'head': '$BRANCH_NAME',
              'base': 'main',
              'body': '🔴 **AI Security Fix**\n\n| | |\n|---|---|\n| **Rule** | \`$RULE\` |\n| **File** | \`$FILE\` |\n| **Severity** | $SEVERITY |\n\n---\n⚠️ Review before merging.\n_🤖 ${OLLAMA_MODEL}_'
          }
          with open('/tmp/pr.json', 'w') as f:
              json.dump(pr, f)
          "

            PR_RESPONSE=$(curl -sS -X POST \
              -H "Authorization: token ${GITHUB_TOKEN}" \
              -H "Accept: application/vnd.github.v3+json" \
              "https://api.github.com/repos/${REPO}/pulls" \
              -d @/tmp/pr.json 2>/dev/null)

            PR_URL=$(echo "$PR_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('html_url',''))" 2>/dev/null)

            if [ -n "$PR_URL" ] && [ "$PR_URL" != "None" ] && [ "$PR_URL" != "" ]; then
              echo "       ✔ PR created: ${PR_URL}"
              FIX_PRS="${FIX_PRS}\n  - ${PR_URL}"
              FIXED=$((FIXED + 1))
            else
              echo "       ⚠ PR creation failed"
              echo "       $(echo "$PR_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message',''))" 2>/dev/null)"
              FAILED=$((FAILED + 1))
            fi

            git checkout main 2>/dev/null
            echo ""
          done

          # ── Summary ──────────────────────────────────────
          echo "════════════════════════════════════════════════"
          echo "  AI REMEDIATION SUMMARY"
          echo "════════════════════════════════════════════════"
          echo "  Total processed:  ${TOTAL}"
          echo "  PRs created:      ${FIXED}"
          echo "  Failed:           ${FAILED}"
          echo "  Model:            ${OLLAMA_MODEL}"
          if [ -n "$FIX_PRS" ]; then
            echo ""
            echo "  Fix PRs:"
            echo -e "$FIX_PRS"
          fi
          echo "════════════════════════════════════════════════"

      - name: Cleanup
        if: always()
        run: |
          pkill ollama 2>/dev/null || true
