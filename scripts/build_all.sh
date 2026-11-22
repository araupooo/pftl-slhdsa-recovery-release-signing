#!/bin/bash
# build_all.sh — build the pinned stack from pack/fixtures/:
#   liboqs 0.16.0 (optimized, OQS_OPT_TARGET=auto, lib only) and the four
#   harness binaries (src/bench_sig.c, src/bench_slhdsa.c, src/release.c,
#   src/recovery.c) linked against it.
# No oqs-provider is needed: ML-DSA and SLH-DSA are used through the liboqs
# C API (OQS_SIG) and Ed25519 through the system OpenSSL 3 EVP API.
# Usage: build_all.sh [workdir]
# workdir defaults to <task>/work. Skips the build when the install and
# all binaries already exist (set FORCE_BUILD=1 to rebuild).
# Logs go to <workdir>/build-*.log. Builds use -j2 (VM has 4 CPUs, ~483 MB
# free RAM at build time; keep concurrency modest).
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${1:-$PACK/../work}"
mkdir -p "$WORK"
# Absolutize WORK: this script cds into it and then still uses "$WORK/..."
# paths, so a relative WORK would double-nest (work/work). Absolute is safe.
WORK="$(cd "$WORK" && pwd)"
cd "$WORK"

if [ "${FORCE_BUILD:-0}" != "1" ] && [ -f "$WORK/install/lib/liboqs.a" ] \
   && [ -f "$WORK/bench_sig" ] && [ -f "$WORK/bench_slhdsa" ] \
   && [ -f "$WORK/release" ] && [ -f "$WORK/recovery" ]; then
  echo "build_all: liboqs and harness binaries already present; skipping (FORCE_BUILD=1 to rebuild)"
  exit 0
fi

set -e
[ -d liboqs-0.16.0 ] || tar xzf "$PACK/fixtures/liboqs-0.16.0.tar.gz"

echo "=== liboqs optimized build (OQS_OPT_TARGET=auto) ==="
cmake -S liboqs-0.16.0 -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=auto \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$WORK/install" > build-cmake.log 2>&1
cmake --build build -j2 > build-make.log 2>&1
cmake --install build > build-install.log 2>&1

echo "=== harness binaries ==="
cc -O2 -I"$WORK/install/include" "$PACK/src/bench_sig.c" \
  -L"$WORK/install/lib" -loqs -lcrypto -o "$WORK/bench_sig"
cc -O2 -I"$WORK/install/include" "$PACK/src/bench_slhdsa.c" \
  -L"$WORK/install/lib" -loqs -lcrypto -o "$WORK/bench_slhdsa"
cc -O2 -I"$WORK/install/include" "$PACK/src/release.c" \
  -L"$WORK/install/lib" -loqs -lcrypto -o "$WORK/release"
cc -O2 -I"$WORK/install/include" "$PACK/src/recovery.c" \
  -L"$WORK/install/lib" -loqs -lcrypto -o "$WORK/recovery"
echo "build_all: DONE"
"$WORK/bench_slhdsa" --help 2>/dev/null | head -2 || true
sha256sum "$WORK/bench_sig" "$WORK/bench_slhdsa" "$WORK/release" "$WORK/recovery"
