#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="elf_fuzzer macho_fuzzer pe_fuzzer pkcs7_signature pme_fuzzer"

# Compilers reach cmake through the exported CC/CXX env (by name), NOT -DCMAKE_C_COMPILER: passing the bare
# name on a re-run differs from the cached /usr/bin path, so cmake wipes the cache and drops the -D options.
# 1) LIEF itself, instrumented (sanitizers + DWARF 3 + SanCov), static. Third-party sources come from
#    third-party/*.zip in the tree, so this is air-gapped. Build dirs live under build/ (gitignored upstream).
FUZZ_BUILD="$SRC/build/fuzz"
cmake -S "$SRC" -B "$FUZZ_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-O2 -DNDEBUG" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
  -DBUILD_SHARED_LIBS=OFF -DLIEF_EXAMPLES=OFF -DLIEF_TESTS=OFF -DLIEF_INSTALL=OFF \
  -DLIEF_USE_CCACHE=OFF -DLIEF_PYTHON_API=OFF
cmake --build "$FUZZ_BUILD" -j"$MAYHEM_JOBS" --target LIB_LIEF

# 2) Harnesses (upstream's own fuzzing/*.cpp), each as a libFuzzer binary and a standalone reproducer.
LIEF_INC=(-I"$SRC/include" -I"$FUZZ_BUILD/include")
LIEF_A="$FUZZ_BUILD/libLIEF.a"
[ -f "$LIEF_A" ] || { echo "missing $LIEF_A" >&2; exit 1; }
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ_BUILD/lsan_off.o"
for t in $TARGETS; do
  $CXX -std=c++17 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/fuzzing/$t.cpp" "$FUZZ_BUILD/lsan_off.o" "${LIEF_INC[@]}" "$LIEF_A" -o "$SRC/$t"
  $CXX -std=c++17 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/fuzzing/$t.cpp" "$FUZZ_BUILD/standalone_main.o" "$FUZZ_BUILD/lsan_off.o" "${LIEF_INC[@]}" "$LIEF_A" -o "$SRC/$t-standalone"
done

# 3) Test build: NORMAL flags (no sanitizers, no -gdwarf-3), separate build dir. Runs upstream's Catch2
#    unittests (the sample-free subset, see test.sh) plus mayhem/oracle.cpp, a known-answer probe.
TEST_BUILD="$SRC/build/tests"
cmake -S "$SRC" -B "$TEST_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DBUILD_SHARED_LIBS=OFF -DLIEF_EXAMPLES=OFF -DLIEF_TESTS=ON -DLIEF_USE_MELKOR=OFF -DLIEF_INSTALL=OFF \
  -DLIEF_USE_CCACHE=OFF -DLIEF_PYTHON_API=OFF
cmake --build "$TEST_BUILD" -j"$MAYHEM_JOBS" --target unittests
[ -x "$TEST_BUILD/tests/unittests/unittests" ] || { echo "unittests not built" >&2; exit 1; }
$CXX -std=c++17 -O1 $COVERAGE_FLAGS "$SRC/mayhem/oracle.cpp" -I"$SRC/include" -I"$TEST_BUILD/include" \
  "$TEST_BUILD/libLIEF.a" -o "$SRC/lief-oracle"
