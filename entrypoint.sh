#!/usr/bin/env bash
# entrypoint.sh - codespy GitHub Action entrypoint
#
# Orchestrates the security scan inside GitHub Actions:
#   - Detects PR context and collects changed files
#   - Runs codespy with the appropriate arguments
#   - Writes a GitHub Actions step summary
#   - Posts a PR comment via the GitHub API (if enabled)
#   - Generates SARIF output (if enabled)
#   - Exits with the appropriate code based on severity threshold
#
# All inputs are read from environment variables set by action.yml.

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────

severity_rank() {
  case "$1" in
    critical) echo 5 ;;
    high)     echo 4 ;;
    medium)   echo 3 ;;
    low)      echo 2 ;;
    info)     echo 1 ;;
    *)        echo 0 ;;
  esac
}

# ── Inputs ───────────────────────────────────────────────────────────────────

SCAN_PATH="${INPUT_PATH:-.}"
SEVERITY="${INPUT_SEVERITY_THRESHOLD:-high}"
OUTPUT_FORMAT="${INPUT_OUTPUT_FORMAT:-markdown}"
SCAN_CHANGED="${INPUT_SCAN_CHANGED_ONLY:-true}"
POST_COMMENT="${INPUT_POST_COMMENT:-true}"
FAIL_ON="${INPUT_FAIL_ON_FINDINGS:-true}"
SARIF_UPLOAD="${INPUT_SARIF_UPLOAD:-false}"
SHOW_FIXES="${INPUT_SHOW_FIXES:-true}"
CODESPY="${CODESPY_SCRIPT:-codespy.py}"

IS_PR="false"
PR_NUMBER=""
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ] || [ "${GITHUB_EVENT_NAME:-}" = "pull_request_target" ]; then
  IS_PR="true"
  # Extract PR number from the event payload
  if [ -n "${GITHUB_EVENT_PATH:-}" ] && [ -f "${GITHUB_EVENT_PATH}" ]; then
    PR_NUMBER=$(python3 -c "import json; print(json.load(open('${GITHUB_EVENT_PATH}'))['pull_request']['number'])" 2>/dev/null || echo "")
  fi
fi

echo "::group::codespy configuration"
echo "  Path:              ${SCAN_PATH}"
echo "  Severity threshold: ${SEVERITY}"
echo "  Output format:     ${OUTPUT_FORMAT}"
echo "  Scan changed only: ${SCAN_CHANGED}"
echo "  Post PR comment:   ${POST_COMMENT}"
echo "  Fail on findings:  ${FAIL_ON}"
echo "  SARIF upload:      ${SARIF_UPLOAD}"
echo "  Show fixes:        ${SHOW_FIXES}"
echo "  Is PR:             ${IS_PR}"
echo "  PR number:         ${PR_NUMBER:-N/A}"
echo "::endgroup::"

# ── Collect changed files (PR mode) ─────────────────────────────────────────

CHANGED_FILES_ARGS=""
CHANGED_FILES_LIST=""
CHANGED_COUNT="all"

if [ "${IS_PR}" = "true" ] && [ "${SCAN_CHANGED}" = "true" ]; then
  echo "::group::Detecting changed files in PR"

  # Ensure we have enough git history to compute the diff
  git fetch origin "${GITHUB_BASE_REF:-main}" --depth=1 2>/dev/null || true

  CHANGED_FILES_LIST=$(git diff --name-only --diff-filter=ACMR "origin/${GITHUB_BASE_REF:-main}"...HEAD 2>/dev/null || echo "")

  if [ -n "${CHANGED_FILES_LIST}" ]; then
    CHANGED_COUNT=$(echo "${CHANGED_FILES_LIST}" | wc -l | tr -d ' ')
    echo "Found ${CHANGED_COUNT} changed file(s):"
    echo "${CHANGED_FILES_LIST}" | head -50
    if [ "${CHANGED_COUNT}" -gt 50 ]; then
      echo "  ... and $((CHANGED_COUNT - 50)) more"
    fi

    # Build the --files argument
    CHANGED_FILES_ARGS="--files"
    while IFS= read -r f; do
      if [ -f "${f}" ]; then
        CHANGED_FILES_ARGS="${CHANGED_FILES_ARGS} ${f}"
      fi
    done <<< "${CHANGED_FILES_LIST}"
  else
    echo "No changed files detected or unable to compute diff. Scanning all files."
  fi
  echo "::endgroup::"
fi

# ── Run the scan ─────────────────────────────────────────────────────────────

JSON_TMPFILE=$(mktemp /tmp/codespy-json-XXXXXX.json)
REPORT_TMPFILE=$(mktemp /tmp/codespy-report-XXXXXX.txt)
SARIF_FILE="codespy-results.sarif"

# Always produce JSON for metadata extraction
echo "::group::Running codespy scan (JSON metadata pass)"
CMD_JSON="python3 ${CODESPY} ${SCAN_PATH} --severity ${SEVERITY} --format json -o ${JSON_TMPFILE} --no-color"
if [ "${SHOW_FIXES}" = "true" ]; then
  CMD_JSON="${CMD_JSON} --fix"
fi
if [ -n "${CHANGED_FILES_ARGS}" ] && [ "${CHANGED_FILES_ARGS}" != "--files" ]; then
  CMD_JSON="${CMD_JSON} ${CHANGED_FILES_ARGS}"
fi
echo "$ ${CMD_JSON}"
eval ${CMD_JSON} || true
echo "::endgroup::"

# Extract metadata from JSON
TOTAL=0; CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; SCORE=100; GRADE="A+"

if [ -f "${JSON_TMPFILE}" ] && [ -s "${JSON_TMPFILE}" ]; then
  TOTAL=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('total_findings', 0))" 2>/dev/null || echo "0")
  CRITICAL=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('severity_counts', {}).get('critical', 0))" 2>/dev/null || echo "0")
  HIGH=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('severity_counts', {}).get('high', 0))" 2>/dev/null || echo "0")
  MEDIUM=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('severity_counts', {}).get('medium', 0))" 2>/dev/null || echo "0")
  LOW=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('severity_counts', {}).get('low', 0))" 2>/dev/null || echo "0")
  INFO=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('severity_counts', {}).get('info', 0))" 2>/dev/null || echo "0")
  SCORE=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('security_score', 100))" 2>/dev/null || echo "100")
  GRADE=$(python3 -c "import json; d=json.load(open('${JSON_TMPFILE}')); print(d.get('security_grade', 'A+'))" 2>/dev/null || echo "A+")
fi

# Set outputs
echo "total_findings=${TOTAL}" >> "${GITHUB_OUTPUT}"
echo "critical_count=${CRITICAL}" >> "${GITHUB_OUTPUT}"
echo "high_count=${HIGH}" >> "${GITHUB_OUTPUT}"
echo "medium_count=${MEDIUM}" >> "${GITHUB_OUTPUT}"
echo "low_count=${LOW}" >> "${GITHUB_OUTPUT}"
echo "security_score=${SCORE}" >> "${GITHUB_OUTPUT}"
echo "security_grade=${GRADE}" >> "${GITHUB_OUTPUT}"

echo "::group::Scan results summary"
echo "  Total findings:  ${TOTAL}"
echo "  Critical:        ${CRITICAL}"
echo "  High:            ${HIGH}"
echo "  Medium:          ${MEDIUM}"
echo "  Low:             ${LOW}"
echo "  Info:            ${INFO}"
echo "  Security score:  ${SCORE}/100 (${GRADE})"
echo "::endgroup::"

# ── Generate formatted report ────────────────────────────────────────────────

echo "::group::Generating ${OUTPUT_FORMAT} report"
CMD_REPORT="python3 ${CODESPY} ${SCAN_PATH} --severity ${SEVERITY} --format ${OUTPUT_FORMAT} -o ${REPORT_TMPFILE} --no-color"
if [ "${SHOW_FIXES}" = "true" ]; then
  CMD_REPORT="${CMD_REPORT} --fix"
fi
if [ -n "${CHANGED_FILES_ARGS}" ] && [ "${CHANGED_FILES_ARGS}" != "--files" ]; then
  CMD_REPORT="${CMD_REPORT} ${CHANGED_FILES_ARGS}"
fi
echo "$ ${CMD_REPORT}"
eval ${CMD_REPORT} || true
echo "report_file=${REPORT_TMPFILE}" >> "${GITHUB_OUTPUT}"
echo "::endgroup::"

# ── Generate SARIF (if needed) ───────────────────────────────────────────────

if [ "${SARIF_UPLOAD}" = "true" ]; then
  echo "::group::Generating SARIF output"
  CMD_SARIF="python3 ${CODESPY} ${SCAN_PATH} --severity ${SEVERITY} --format sarif -o ${SARIF_FILE} --no-color"
  if [ -n "${CHANGED_FILES_ARGS}" ] && [ "${CHANGED_FILES_ARGS}" != "--files" ]; then
    CMD_SARIF="${CMD_SARIF} ${CHANGED_FILES_ARGS}"
  fi
  echo "$ ${CMD_SARIF}"
  eval ${CMD_SARIF} || true
  echo "sarif_file=${SARIF_FILE}" >> "${GITHUB_OUTPUT}"
  echo "SARIF written to ${SARIF_FILE}"
  echo "::endgroup::"
fi

# ── Write GitHub Actions step summary ────────────────────────────────────────

echo "::group::Writing step summary"

{
  echo "## :shield: codespy Security Scan Results"
  echo ""

  # Badge-style grade
  if [ "${SCORE}" -ge 90 ]; then
    GRADE_ICON=":white_check_mark:"
  elif [ "${SCORE}" -ge 70 ]; then
    GRADE_ICON=":large_orange_diamond:"
  else
    GRADE_ICON=":red_circle:"
  fi

  echo "${GRADE_ICON} **Security Score: ${SCORE}/100 (Grade: ${GRADE})**"
  echo ""

  # Scan scope
  if [ "${IS_PR}" = "true" ] && [ "${SCAN_CHANGED}" = "true" ] && [ "${CHANGED_COUNT}" != "all" ]; then
    echo "> Scanned **${CHANGED_COUNT} changed file(s)** in this pull request."
  else
    echo "> Full repository scan."
  fi
  echo ""

  # Severity table
  echo "| Severity | Count |"
  echo "|----------|------:|"
  if [ "${CRITICAL}" -gt 0 ]; then
    echo "| :red_circle: **Critical** | **${CRITICAL}** |"
  fi
  if [ "${HIGH}" -gt 0 ]; then
    echo "| :orange_circle: **High** | **${HIGH}** |"
  fi
  if [ "${MEDIUM}" -gt 0 ]; then
    echo "| :yellow_circle: Medium | ${MEDIUM} |"
  fi
  if [ "${LOW}" -gt 0 ]; then
    echo "| :large_blue_circle: Low | ${LOW} |"
  fi
  if [ "${INFO}" -gt 0 ]; then
    echo "| :white_circle: Info | ${INFO} |"
  fi
  if [ "${TOTAL}" -eq 0 ]; then
    echo "| :white_check_mark: **No findings** | 0 |"
  fi
  echo "| **Total** | **${TOTAL}** |"
  echo ""

  # Detailed findings in a collapsed section (from JSON data)
  if [ "${TOTAL}" -gt 0 ] && [ -f "${JSON_TMPFILE}" ] && [ -s "${JSON_TMPFILE}" ]; then
    echo "<details>"
    echo "<summary>View detailed findings (${TOTAL})</summary>"
    echo ""

    # Generate findings table from JSON
    python3 -c "
import json, sys
d = json.load(open('${JSON_TMPFILE}'))
findings = d.get('findings', [])
if findings:
    print('| Severity | File | Line | Rule | Title |')
    print('|----------|------|-----:|------|-------|')
    icons = {
        'critical': ':red_circle:',
        'high': ':orange_circle:',
        'medium': ':yellow_circle:',
        'low': ':large_blue_circle:',
        'info': ':white_circle:'
    }
    for f in findings[:100]:
        sev = f['severity']
        icon = icons.get(sev, ':white_circle:')
        path = f['file_path']
        if len(path) > 40:
            path = '...' + path[-37:]
        title = f['title']
        print(f'| {icon} {sev.upper()} | \`{path}\` | {f[\"line_number\"]} | {f[\"rule_id\"]} | {title} |')
    if len(findings) > 100:
        print(f'| | | | | *... and {len(findings) - 100} more findings* |')
" 2>/dev/null || echo "_Could not render findings table._"

    echo ""
    echo "</details>"
    echo ""
  fi

  echo "---"
  echo "*Scanned by [codespy](https://github.com/wisent-ai/codespy) -- fast, offline code security scanner.*"

} >> "${GITHUB_STEP_SUMMARY}"

echo "Step summary written."
echo "::endgroup::"

# ── Post PR comment ──────────────────────────────────────────────────────────

if [ "${IS_PR}" = "true" ] && [ "${POST_COMMENT}" = "true" ] && [ -n "${PR_NUMBER}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  echo "::group::Posting PR comment"

  # Build comment body
  COMMENT_BODY=$(python3 -c "
import json, sys

d = json.load(open('${JSON_TMPFILE}'))
total = d.get('total_findings', 0)
score = d.get('security_score', 100)
grade = d.get('security_grade', 'A+')
sc = d.get('severity_counts', {})
findings = d.get('findings', [])

lines = []
lines.append('## :shield: codespy Security Scan')
lines.append('')

if score >= 90:
    icon = ':white_check_mark:'
elif score >= 70:
    icon = ':large_orange_diamond:'
else:
    icon = ':red_circle:'

lines.append(f'{icon} **Security Score: {score}/100 (Grade: {grade})**')
lines.append('')

scan_note = '${CHANGED_COUNT}' if '${CHANGED_COUNT}' != 'all' else 'all'
if scan_note != 'all':
    lines.append(f'> Scanned **{scan_note} changed file(s)** in this pull request.')
else:
    lines.append('> Full repository scan.')
lines.append('')

if total == 0:
    lines.append(':tada: **No security findings detected.** Great job!')
else:
    lines.append('| Severity | Count |')
    lines.append('|----------|------:|')
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    icons_map = {
        'critical': ':red_circle:',
        'high': ':orange_circle:',
        'medium': ':yellow_circle:',
        'low': ':large_blue_circle:',
        'info': ':white_circle:'
    }
    for sev in severity_order:
        c = sc.get(sev, 0)
        if c > 0:
            bold = '**' if sev in ('critical', 'high') else ''
            lines.append(f'| {icons_map[sev]} {sev.upper()} | {bold}{c}{bold} |')
    lines.append(f'| **Total** | **{total}** |')
    lines.append('')

    # Top findings (max 15)
    if findings:
        lines.append('<details>')
        lines.append(f'<summary>Top findings ({min(len(findings), 15)} of {len(findings)})</summary>')
        lines.append('')
        for f in findings[:15]:
            sev = f['severity']
            icon = icons_map.get(sev, ':white_circle:')
            suggestion = ''
            if f.get('suggestion'):
                suggestion = f' -- {f[\"suggestion\"]}'
            lines.append(f'- {icon} **[{f[\"rule_id\"]}] {f[\"title\"]}** (\`{f[\"file_path\"]}:{f[\"line_number\"]}\`)')
            lines.append(f'  {f[\"description\"]}{suggestion}')
        if len(findings) > 15:
            lines.append(f'')
            lines.append(f'*... and {len(findings) - 15} more findings. See the Actions step summary for the full report.*')
        lines.append('')
        lines.append('</details>')

lines.append('')
lines.append('---')
lines.append('*[codespy](https://github.com/wisent-ai/codespy) -- fast, offline code security scanner*')

print(json.dumps('\n'.join(lines)))
" 2>/dev/null || echo '""')

  if [ -n "${COMMENT_BODY}" ] && [ "${COMMENT_BODY}" != '""' ]; then
    # Look for an existing codespy comment to update (avoid spam)
    EXISTING_COMMENT_ID=$(curl -s \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100" \
      2>/dev/null | python3 -c "
import json, sys
comments = json.load(sys.stdin)
for c in comments:
    if ':shield: codespy Security Scan' in c.get('body', ''):
        print(c['id'])
        break
" 2>/dev/null || echo "")

    if [ -n "${EXISTING_COMMENT_ID}" ]; then
      # Update existing comment
      echo "Updating existing comment ${EXISTING_COMMENT_ID}"
      curl -s -X PATCH \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_COMMENT_ID}" \
        -d "{\"body\": ${COMMENT_BODY}}" > /dev/null 2>&1 || echo "::warning::Failed to update PR comment"
    else
      # Create new comment
      echo "Creating new PR comment"
      curl -s -X POST \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
        -d "{\"body\": ${COMMENT_BODY}}" > /dev/null 2>&1 || echo "::warning::Failed to post PR comment"
    fi

    echo "PR comment posted successfully."
  else
    echo "::warning::Could not generate PR comment body."
  fi

  echo "::endgroup::"
fi

# ── Determine exit code ──────────────────────────────────────────────────────

if [ "${FAIL_ON}" = "false" ] || [ "${FAIL_ON}" = "none" ]; then
  echo "fail-on-findings is disabled. Exiting with success."
  rm -f "${JSON_TMPFILE}" "${REPORT_TMPFILE}"
  exit 0
fi

# If fail-on-findings is true, use the severity-threshold to decide
THRESHOLD_RANK=$(severity_rank "${SEVERITY}")
SHOULD_FAIL=0

# Check each severity level at or above the threshold
if [ "$(severity_rank critical)" -ge "${THRESHOLD_RANK}" ] && [ "${CRITICAL}" -gt 0 ]; then
  SHOULD_FAIL=1
fi
if [ "$(severity_rank high)" -ge "${THRESHOLD_RANK}" ] && [ "${HIGH}" -gt 0 ]; then
  SHOULD_FAIL=1
fi
if [ "$(severity_rank medium)" -ge "${THRESHOLD_RANK}" ] && [ "${MEDIUM}" -gt 0 ]; then
  SHOULD_FAIL=1
fi
if [ "$(severity_rank low)" -ge "${THRESHOLD_RANK}" ] && [ "${LOW}" -gt 0 ]; then
  SHOULD_FAIL=1
fi
if [ "$(severity_rank info)" -ge "${THRESHOLD_RANK}" ] && [ "${INFO}" -gt 0 ]; then
  SHOULD_FAIL=1
fi

rm -f "${JSON_TMPFILE}" "${REPORT_TMPFILE}"

if [ "${SHOULD_FAIL}" -eq 1 ]; then
  echo "::error::codespy found ${TOTAL} finding(s) at or above '${SEVERITY}' severity. Security score: ${SCORE}/100 (${GRADE})."
  exit 1
else
  echo "No findings at or above '${SEVERITY}' severity. Scan passed."
  exit 0
fi
