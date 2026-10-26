#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# 1) Upstream's Catch2 unittests. The suite's sample-driven cases need LIEF_SAMPLES_DIR (a separate
#    ~GB download we cannot ship), so run exactly the cases that need no samples and assert the count.
UNITTESTS="$SRC/build/tests/tests/unittests/unittests"
[ -x "$UNITTESTS" ] || { echo "missing $UNITTESTS (build.sh should have built it)" >&2; emit_ctrf "catch2+kat" 0 1 0; exit 1; }
CASES="lief.test.iterators.value_semantics,lief.test.hash,lief.test.enums_bitmask,lief.test.const_ref_iterator,lief.test.filter_ref_iterator,lief.test.iostream,lief.test.const_filter_ref_iterator,lief.test.ref_iterator,lief.test.utils"
EXPECTED_CASES=9
out="$("$UNITTESTS" "$CASES" 2>&1)"; rc=$?
printf '%s\n' "$out" | tail -5
passed=0; failed=0
if [[ "$out" =~ All\ tests\ passed\ \(([0-9]+)\ assertions?\ in\ ([0-9]+)\ test\ cases?\) ]]; then
  passed="${BASH_REMATCH[2]}"
elif [[ "$out" =~ test\ cases:\ +([0-9]+)\ \|\ +([0-9]+)\ passed\ \|\ +([0-9]+)\ failed ]]; then
  passed="${BASH_REMATCH[2]}"; failed="${BASH_REMATCH[3]}"
else
  failed=1
fi
[ "$rc" -eq 0 ] || [ "$failed" -gt 0 ] || failed=1
if [ "$failed" -eq 0 ] && [ "$passed" -ne "$EXPECTED_CASES" ]; then
  echo "expected $EXPECTED_CASES unittest cases, ran $passed" >&2; failed=1
fi

# 2) Known-answer probe: parse committed ELF/Mach-O/PE/Authenticode inputs with the built library and
#    diff the dump against golden values. A neutered or broken parser prints nothing / different values.
ORACLE="$SRC/lief-oracle"
[ -x "$ORACLE" ] || { echo "missing $ORACLE (build.sh should have built it)" >&2; emit_ctrf "catch2+kat" "$passed" $((failed + 1)) 0; exit 1; }
actual="$("$ORACLE" "$SRC" 2>&1)"
if diff <(printf '%s\n' "$actual") "$SRC/mayhem/oracle.expected" > "${TMPDIR:-/tmp}/oracle.diff"; then
  kat_pass=1; kat_fail=0
else
  head -30 "${TMPDIR:-/tmp}/oracle.diff" >&2; kat_pass=0; kat_fail=1
fi

emit_ctrf "catch2+kat" $((passed + kat_pass)) $((failed + kat_fail)) 0
