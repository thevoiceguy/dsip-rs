# A Debian trixie with systemd as PID 1, to install the .deb and run the hardened unit for real (packaging/test.sh).
FROM debian:trixie
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv curl ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/* && systemctl mask systemd-logind.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
