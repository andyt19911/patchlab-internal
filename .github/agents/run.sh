#!/usr/bin/env bash
# Run one PatchLab agent (operator or analyst): run.sh NAME ALLOWED_COMMAND...
#
# The agent works on copies: a git worktree of this checkout and a copy of the
# estate's state (and, for the operator, the repo mirrors, which `discover` reads).
# It gets an empty environment apart from its API key, so no repo token reaches it,
# and restricted mode with Bash limited to the commands given here. Its tools come
# from a venv installed from this commit before it ran, so nothing it edits runs.
# What it produces is taken back by trusted code: `operator import-results`, and the
# operator's patch, which is guarded and tested in a job without secrets.
set -euo pipefail
name=$1; shift
root="$RUNNER_TEMP/agents/$name"
tools="$RUNNER_TEMP/agents/tools"
rm -rf "$root"; mkdir -p "$root/estate" "$root/notes" "$root/home"
git worktree add --detach "$root/src" HEAD >/dev/null
cp -a "$PATCHLAB_INTERNAL_ESTATE_WORKDIR/state" "$root/estate/state"
rm -f "$root/estate/state/.lock"
if [ "$name" = operator ] && [ -d "$PATCHLAB_INTERNAL_ESTATE_WORKDIR/repos" ]; then
  cp -a "$PATCHLAB_INTERNAL_ESTATE_WORKDIR/repos" "$root/estate/repos"
fi
allowed=()
for c in "$@"; do allowed+=("Bash($c)"); done
notes_var="$(echo "$name" | tr '[:lower:]' '[:upper:]')_NOTES"
cd "$root/src"
set +e
env -i PATH="$tools/venv/bin:$tools/node/node_modules/.bin:/usr/local/bin:/usr/bin:/bin" \
  HOME="$root/home" LANG=C.UTF-8 ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  PATCHLAB_INTERNAL_ESTATE_WORKDIR="$root/estate" \
  PATCHLAB_INTERNAL_AGENT_REPOS="$PATCHLAB_INTERNAL_AGENT_REPOS" \
  "$notes_var=$root/notes" \
  timeout "${AGENT_MINUTES:-40}m" \
  claude -p "$(cat "$GITHUB_WORKSPACE/.github/agents/$name.md")" \
    --bare --restricted --strict-mcp-config \
    --tools "Read,Edit,Write,Glob,Grep,Bash" \
    --add-dir "$root/estate/state" "$root/notes" \
    --permission-mode acceptEdits --max-budget-usd "${AGENT_BUDGET_USD:-5}" \
    --output-format text \
    --allowedTools "${allowed[@]}" > "$root/summary.md"
rc=$?
set -e
{ echo "## The $name"; echo; cat "$root/summary.md"; echo; } >> "$GITHUB_STEP_SUMMARY"
if [ "$name" = operator ]; then
  git add -A
  git diff --cached --binary HEAD > "$root/operator.patch"
  git rev-parse HEAD > "$root/base.txt"
fi
exit $rc
