#!/usr/bin/env bash
# Build the service packages into crates/<service>/dist/, for dsip-relay, dsip-mailbox and dsip-push (or those named):
#   static binaries (musl; x86_64 and aarch64) and their .tar.gz, the .deb for each, SHA256SUMS, and (with --image)
#   the container image for this machine's architecture, loaded into the local Docker as <service>:<version> and
#   <service>:dev. Named dsip-web, the browser client as web/dist/dsip-web-<version>.tar.gz, what the relay serves
#   with --www (web/build.sh first, if web/pkg is not built).
#   packaging/build.sh [--image] [dsip-relay] [dsip-mailbox] [dsip-push] [dsip-web]
# Needs: the musl targets (`rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl`), cargo-zigbuild
# with zig (`pip install ziglang`), cargo-deb, Docker for --image, wasm-pack for dsip-web. dsip-node builds with its own
# crates/dsip-node/packaging/build.sh.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
IMAGE=; WEB=; SERVICES=()
for a in "$@"; do
  case $a in
    --image) IMAGE=1 ;;
    dsip-web) WEB=1 ;;
    dsip-relay|dsip-mailbox|dsip-push) SERVICES+=("$a") ;;
    *) echo "usage: $0 [--image] [dsip-relay] [dsip-mailbox] [dsip-push] [dsip-web]"; exit 2 ;;
  esac
done
[ ${#SERVICES[@]} -gt 0 ] || [ -n "$WEB" ] || SERVICES=(dsip-relay dsip-mailbox dsip-push)
# The runner's CMake 4 refuses projects declaring cmake_minimum_required < 3.5 (aws-lc-sys's build, vendored C)
export CMAKE_POLICY_VERSION_MINIMUM=${CMAKE_POLICY_VERSION_MINIMUM:-3.5}
version() {
  cargo metadata --no-deps --format-version 1 --manifest-path "$ROOT/Cargo.toml" \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]==sys.argv[1]))' "$1"
}
features() { # the mailbox links SQLite and OpenSSL: compiled in for a static binary
  [ "$1" = dsip-mailbox ] && echo "--features static" || true
}
for svc in "${SERVICES[@]+"${SERVICES[@]}"}"; do
  CRATE=$ROOT/crates/$svc; VERSION=$(version "$svc")
  rm -rf "$CRATE/dist"; mkdir -p "$CRATE/dist"
  for pair in amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl; do
    arch=${pair%%:*}; target=${pair#*:}; log=$CRATE/dist/build-$arch.log
    # zig's libc headers warn loudly and harmlessly; keep the log, and show all of it if the build fails
    # shellcheck disable=SC2046
    if ! cargo zigbuild --release --locked --target "$target" -p "$svc" --bin "$svc" $(features "$svc") >"$log" 2>&1; then
      tail -60 "$log"; echo "build of $svc for $target failed (full log: $log)"; exit 1
    fi
    mkdir -p "$CRATE/dist/$arch"
    cp "target/$target/release/$svc" "$CRATE/dist/$arch/$svc"
    tar -czf "$CRATE/dist/$svc-$VERSION-linux-$arch.tar.gz" -C "$CRATE/dist/$arch" "$svc" -C "$CRATE" config.example.toml \
      -C "$CRATE/packaging/debian" "$svc.service" -C "$ROOT/packaging" install-certificate
    cargo deb -q -p "$svc" --target "$target" --no-build --no-strip --output "$CRATE/dist/" >/dev/null
    echo "built $svc $arch: $(file -b "$CRATE/dist/$arch/$svc" | cut -d, -f1-2,5), $(ls "$CRATE"/dist/*_"$arch".deb | xargs -n1 basename)"
  done
  (cd "$CRATE/dist" && sha256sum -- *.tar.gz *.deb > SHA256SUMS)
  if [ -n "$IMAGE" ]; then
    arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
    mkdir -p "$CRATE/dist/state"  # the image's empty, owned state directory (Containerfile): no busybox stage pulled
    docker build -q --build-arg TARGETARCH="$arch" -f "$CRATE/packaging/Containerfile" -t "$svc:$VERSION" -t "$svc:dev" "$CRATE" >/dev/null
    echo "image $svc:$VERSION ($arch), $(docker image inspect "$svc:dev" --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1e6}')"
  fi
done
if [ -n "$WEB" ]; then
  # the browser client as the relay serves it (--www): the page, its host modules and the built engine
  VERSION=$(python3 -c 'import json; print(json.load(open("web/package.json"))["version"])')
  [ -f web/pkg/dsip_wasm_bg.wasm ] || web/build.sh
  rm -rf web/dist; mkdir -p "web/dist/dsip-web-$VERSION"
  cp -r web/index.html web/style.css web/app.js web/host "web/dist/dsip-web-$VERSION/"
  mkdir -p "web/dist/dsip-web-$VERSION/pkg"
  cp web/pkg/*.js web/pkg/*.wasm "web/dist/dsip-web-$VERSION/pkg/"
  tar -czf "web/dist/dsip-web-$VERSION.tar.gz" -C web/dist "dsip-web-$VERSION"
  rm -rf "web/dist/dsip-web-$VERSION"
  (cd web/dist && sha256sum -- "dsip-web-$VERSION.tar.gz" > SHA256SUMS)
  echo "built web/dist/dsip-web-$VERSION.tar.gz ($(du -h "web/dist/dsip-web-$VERSION.tar.gz" | cut -f1))"
fi
