#!/usr/bin/env bash
# Build every dsip-node artifact into crates/dsip-node/dist/:
#   static binaries (musl; x86_64 and aarch64) and their .tar.gz, the .deb for each, and (with --image) the container
#   image for this machine's architecture, loaded into the local Docker as dsip-node:<version>.
# Needs: the musl targets (`rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl`), cargo-zigbuild
# with zig (`pip install ziglang`), cargo-deb, and Docker for --image.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/.."
CRATE=$PWD; IMPL=$(cd ../.. && pwd)
VERSION=$(cargo metadata --no-deps --format-version 1 --manifest-path "$CRATE/Cargo.toml" \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="dsip-node"))')
rm -rf dist; mkdir -p dist
for pair in amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl; do
  arch=${pair%%:*}; target=${pair#*:}
  (cd "$IMPL" && cargo zigbuild -q --release --locked --target "$target" -p dsip-node 2>&1 | grep -vE 'linker stderr|deprecated|GETFUNCSYM|conflicting prototype|^\s*(\||[0-9]+ \|)|^\s*$|^\s*=|^\s*\^|In file included' || true)
  mkdir -p "dist/$arch"
  cp "$IMPL/target/$target/release/dsip-node" "dist/$arch/dsip-node"
  tar -czf "dist/dsip-node-$VERSION-linux-$arch.tar.gz" -C "dist/$arch" dsip-node -C "$CRATE" config.example.toml \
    -C "$CRATE/packaging/debian" dsip-node.service
  (cd "$IMPL" && cargo deb -q -p dsip-node --target "$target" --no-build --no-strip --output "$CRATE/dist/" >/dev/null)
  echo "built $arch: $(file -b "dist/$arch/dsip-node" | cut -d, -f1-2,5), $(ls dist/*_"$arch".deb | xargs -n1 basename)"
done
(cd dist && sha256sum -- *.tar.gz *.deb > SHA256SUMS)
if [ "${1:-}" = "--image" ]; then
  arch=$(dpkg --print-architecture 2>/dev/null || echo amd64)
  docker build -q --build-arg TARGETARCH="$arch" -f packaging/Containerfile -t "dsip-node:$VERSION" -t dsip-node:dev . >/dev/null
  echo "image dsip-node:$VERSION ($arch), $(docker image inspect dsip-node:dev --format '{{.Size}}' | awk '{printf "%.1f MB", $1/1e6}')"
fi
