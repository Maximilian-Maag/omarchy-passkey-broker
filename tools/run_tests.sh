#!/bin/bash
# Every test kind this repository promises, in escalating cost order.
#
#   policy as code -> unit -> regression -> integration -> e2e -> js -> shell -> mutation
#
# Locally: `tools/run_tests.sh`. In CI: .github/workflows/test.yml.
# `SKIP_MUTATION=1` runs everything but the mutation pass (it is the slow one);
# `ONLY=unit,regression` runs a subset.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 1

ONLY="${ONLY:-}"
want() { [ -n "$ONLY" ] || return 0; case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
fail=0
run() {                        # run <label> <command...>
  local label="$1"; shift
  printf '\n=== %s ===\n' "$label"
  if "$@"; then
    printf '%s: ok\n' "$label"
  else
    printf '%s: FAILED (exit %s)\n' "$label" "$?"
    fail=1
  fi
}

if want policy; then
  run "policy as code" python3 tools/policy_check.py
fi

if want unit; then
  run "unit tests (python)" python3 -m unittest discover -s tests -p 'test_unit_*.py' -q
fi

if want regression; then
  run "regression tests (python)" python3 -m unittest discover -s tests -p 'test_regression_*.py' -q
fi

if want integration; then
  if ls tests/test_integration_*.py >/dev/null 2>&1; then
    run "integration tests (python)" python3 -m unittest discover -s tests -p 'test_integration_*.py' -q
  else
    printf '\n=== integration tests ===\nnot applicable to this plugin (no integration surface)\n'
  fi
fi

if want e2e; then
  shopt -s nullglob
  e2e_files=(tests/e2e/test_*.sh)
  if [ ${#e2e_files[@]} -gt 0 ]; then
    for f in "${e2e_files[@]}"; do
      run "e2e tests: $(basename "$f")" bash "$f"
    done
  fi
fi

if want js; then
  shopt -s nullglob
  js_files=(tests/js/*.test.js)
  if [ ${#js_files[@]} -gt 0 ]; then
    for f in "${js_files[@]}"; do
      run "js tests: $(basename "$f")" node --test "$f"
    done
  fi
fi

if want shell; then
  shopt -s nullglob
  sh_files=(tests/shell/test_*.sh)
  if [ ${#sh_files[@]} -gt 0 ]; then
    for f in "${sh_files[@]}"; do
      run "shell tests: $(basename "$f")" bash "$f"
    done
  fi
fi

if want mutation && [ -z "${SKIP_MUTATION:-}" ]; then
  run "mutation tests" python3 tools/mutator.py
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  echo "ALL TEST KINDS PASSED"
else
  echo "SOME TESTS FAILED"
fi
exit "$fail"
