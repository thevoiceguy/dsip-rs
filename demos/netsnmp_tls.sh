#!/usr/bin/env bash
# net-snmp's command-line tools with a working TLS transport, for the SNMP-over-TLS demo. Sourced; sets SNMPTRAP
# and SNMPINFORM (and NETSNMP_ENV, the environment to run them with).
#
# net-snmp before 5.9.5 caps its TLS client at TLS 1.0 (SSL_CTX_set_max_proto_version(…, TLS1_VERSION) in
# snmpTLSTCPDomain.c), which current OpenSSL refuses and rustls never speaks, so its tls: transport cannot connect.
# When the system's snmptrap is older, Debian's 5.9.5.2 packages are fetched (pinned by SHA-256) and unpacked
# locally; only libssl, zlib and zstd are needed from the system.
#
# Spec: none (infrastructure).
NETSNMP_VERSION=5.9.5.2+dfsg-3
NETSNMP_DIR=${NETSNMP_DIR:-$HOME/.cache/dsip-netsnmp-$NETSNMP_VERSION}
declare -A NETSNMP_SHA=(
  [snmp]=c4e29353c5beab6a6ce6ec0224a2ae2da4ec94a4887d31036a40631707062f9d
  [libsnmp45]=092a0115911eddf0af72e7dae1b4ccf0e70072bd118a4080c1d90ff975b1ffc0
)
declare -A NETSNMP_SNAPSHOT=(  # snapshot.debian.org/file/<sha1>, for when the pool has moved on
  [snmp]=91a8c2d7b468556004b6856a2e8f333a764bdf3a
  [libsnmp45]=74b58a6dcd227a8faa852428968e7f5ea6e81971
)

netsnmp_new_enough() {  # the system's snmptrap, if it is 5.9.5 or later
  command -v snmptrap >/dev/null || return 1
  local v; v=$(snmptrap --version 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' | head -1)
  [ "$(printf '%s\n5.9.5\n' "$v" | sort -V | head -1)" = 5.9.5 ]
}

if netsnmp_new_enough; then
  SNMPTRAP=$(command -v snmptrap); SNMPINFORM=$(command -v snmpinform); NETSNMP_ENV=()
else
  if [ ! -x "$NETSNMP_DIR/root/usr/bin/snmptrap" ]; then
    mkdir -p "$NETSNMP_DIR"
    for p in snmp libsnmp45; do
      f="$NETSNMP_DIR/${p}_${NETSNMP_VERSION}_amd64.deb"
      curl -sfL -o "$f" "https://deb.debian.org/debian/pool/main/n/net-snmp/${p}_${NETSNMP_VERSION}_amd64.deb" \
        || curl -sfL -o "$f" "https://snapshot.debian.org/file/${NETSNMP_SNAPSHOT[$p]}"
      echo "${NETSNMP_SHA[$p]}  $f" | sha256sum -c --quiet - || { echo "net-snmp package $p: bad checksum"; exit 1; }
      dpkg -x "$f" "$NETSNMP_DIR/root"
    done
  fi
  SNMPTRAP=$NETSNMP_DIR/root/usr/bin/snmptrap; SNMPINFORM=$NETSNMP_DIR/root/usr/bin/snmpinform
  NETSNMP_ENV=(LD_LIBRARY_PATH="$NETSNMP_DIR/root/usr/lib/x86_64-linux-gnu")
fi
