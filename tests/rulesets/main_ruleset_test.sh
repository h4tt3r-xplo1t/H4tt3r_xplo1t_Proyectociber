#!/bin/bash
# Policy checks for .github/rulesets/main.json (issue #4, phase 2).
#
# The ruleset file is the source of truth applied to GitHub with
# `gh api -X PUT repos/{owner}/{repo}/rulesets/24097824 --input <file>`.
# These checks pin the decisions recorded in
# docs/adr/0001-proteccion-rama-main.md so an edit that weakens the
# protection fails here before it can be applied.
#
# Usage: bash tests/rulesets/main_ruleset_test.sh [path/to/ruleset.json]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RULESET="${1:-$REPO_ROOT/.github/rulesets/main.json}"

# GitHub Actions app id, observed on the check runs of commit a85401a.
GITHUB_ACTIONS_APP_ID=15368

FAILED=0
COUNT=0

# check <description> <jq expression that must evaluate to true>
check() {
  local desc="$1" expr="$2"
  COUNT=$((COUNT + 1))
  if jq -e "$expr" "$RULESET" >/dev/null 2>&1; then
    echo "OK    $desc"
  else
    echo "FALLA $desc"
    FAILED=$((FAILED + 1))
  fi
}

if [ ! -f "$RULESET" ]; then
  echo "FALLA no existe $RULESET"
  exit 1
fi
if ! jq empty "$RULESET" 2>/dev/null; then
  echo "FALLA $RULESET no es JSON valido"
  exit 1
fi

rule() { echo ".rules[] | select(.type == \"$1\")"; }

check "nombre protege, rama, activo" \
  '.name == "protege" and .target == "branch" and .enforcement == "active"'
check "aplica solo a la rama por defecto" \
  '.conditions.ref_name.include == ["~DEFAULT_BRANCH"] and .conditions.ref_name.exclude == []'
check "sin lista de bypass" \
  '.bypass_actors == []'
check "bloquea borrado" \
  "[$(rule deletion)] | length == 1"
check "bloquea force push" \
  "[$(rule non_fast_forward)] | length == 1"
check "exige historial lineal" \
  "[$(rule required_linear_history)] | length == 1"
check "exige pull request con 0 aprobaciones" \
  "$(rule pull_request) | .parameters.required_approving_review_count == 0"
check "descarta aprobaciones obsoletas" \
  "$(rule pull_request) | .parameters.dismiss_stale_reviews_on_push == true"
check "exige conversaciones resueltas" \
  "$(rule pull_request) | .parameters.required_review_thread_resolution == true"
check "solo fusion por squash" \
  "$(rule pull_request) | .parameters.allowed_merge_methods == [\"squash\"]"
check "checks con rama actualizada (strict)" \
  "$(rule required_status_checks) | .parameters.strict_required_status_checks_policy == true"
check "checks requeridos: secretos, workflows, pruebas, gateway" \
  "$(rule required_status_checks) | [.parameters.required_status_checks[].context] | sort == [\"gateway\",\"pruebas\",\"secretos\",\"workflows\"]"
check "cada check fijado a GitHub Actions (integration_id $GITHUB_ACTIONS_APP_ID)" \
  "$(rule required_status_checks) | all(.parameters.required_status_checks[]; .integration_id == $GITHUB_ACTIONS_APP_ID)"
check "sin reglas que bloquean todo cambio o apuntan a herramientas inexistentes" \
  'all(.rules[].type; IN("creation","update","required_signatures","code_scanning","code_quality","code_coverage") | not)'
check "solo los tipos de regla decididos en el ADR" \
  '[.rules[].type] | sort == ["deletion","non_fast_forward","pull_request","required_linear_history","required_status_checks"]'

echo
echo "Total: $COUNT casos, $FAILED fallidos."
[ "$FAILED" -eq 0 ]
