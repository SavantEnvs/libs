#!/usr/bin/env bash
# mayhem/build.sh — libs is a set of single-header C libraries with no build system. Each harness in
# mayhem/harnesses/ is one translation unit that defines <LIB>_IMPLEMENTATION and includes the header,
# so the library code itself is compiled with the sanitizer + debug flags. Outputs go to mayhem/out/
# (gitignored). Also builds mayhem/tests/selftest.c with normal flags for mayhem/test.sh.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must be set (provided by the base image)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"
OUT="$SRC/mayhem/out"
mkdir -p "$OUT/obj"

TARGETS="ini assetsys hoedown id3tag videocodec lzma dialog libxdiff mus opl pathstr speech cstr"

# shared objects: LSan off-switch + the standalone run-once driver
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/obj/lsan_off.o"
$CC  $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# UBSan checks relaxed per target, because the library does it on purpose on every input and the
# fuzzer would otherwise stop at it at once (ASan and every other UBSan check stay on and halting):
#   alignment        - miniz (assetsys), videocodec, cstr (string hash) and id3tag (UTF-16 text frames at odd
#                      byte offsets in the tag) read words through casted pointers
#   pointer-overflow - hoedown/id3tag/miniz compute NULL+0 on empty buffers
#   nonnull-attribute - hoedown memcpy()s from a NULL buffer with length 0
#   shift            - opl/speech/cstr shift into the sign bit / shift negative values (emulator, hash)
relax_for() {
    case "$1" in
        assetsys)            echo "-fno-sanitize=alignment,pointer-overflow" ;;
        videocodec)          echo "-fno-sanitize=alignment" ;;
        cstr)                echo "-fno-sanitize=alignment,shift" ;;
        hoedown)             echo "-fno-sanitize=pointer-overflow,nonnull-attribute" ;;
        id3tag)              echo "-fno-sanitize=alignment,pointer-overflow" ;;
        opl|speech)          echo "-fno-sanitize=shift" ;;
        *)                   echo "" ;;
    esac
}
build_one() {
    t="$1"
    # fuzz object: SanCov-instrumented (fuzzer-no-link) so libFuzzer/Mayhem see the library's edges;
    # standalone object: same flags without SanCov (a plain run-once reproducer).
    # shellcheck disable=SC2046
    $CC $SANITIZER_FLAGS $(relax_for "$t") $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -c "mayhem/harnesses/fuzz_$t.c" -o "$OUT/obj/fuzz_$t.o"
    # shellcheck disable=SC2046
    $CC $SANITIZER_FLAGS $(relax_for "$t") $DEBUG_FLAGS -O1 -c "mayhem/harnesses/fuzz_$t.c" -o "$OUT/obj/fuzz_$t-standalone.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/fuzz_$t.o" "$OUT/obj/lsan_off.o" -lm -o "$OUT/fuzz_$t"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj/standalone_main.o" "$OUT/obj/fuzz_$t-standalone.o" "$OUT/obj/lsan_off.o" -lm -o "$OUT/fuzz_$t-standalone"
}
export -f build_one relax_for
export OUT
# shellcheck disable=SC2086
printf '%s\n' $TARGETS | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'build_one {}'

# functional self-test (known-answer tests over the same headers), NORMAL flags
$CC -O1 $COVERAGE_FLAGS mayhem/tests/selftest.c -lm -o "$OUT/selftest"

for t in $TARGETS; do test -x "$OUT/fuzz_$t" && test -x "$OUT/fuzz_$t-standalone"; done
echo "build.sh: built $(echo $TARGETS | wc -w) targets into $OUT"
