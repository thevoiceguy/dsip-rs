# A Debian trixie with systemd as PID 1, to install a .deb and run its hardened unit for real (the packages' test.sh).
# The official Debian image. test.sh pulls it (ECR Public, then Google's Docker Hub mirror, with retries: anonymous pulls
# from CI runners get HTTP 429 from Docker Hub and, at times, ECR Public) and passes the local tag as BASE.
ARG BASE=public.ecr.aws/docker/library/debian:trixie
FROM $BASE
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv curl ca-certificates procps >/dev/null \
 && rm -rf /var/lib/apt/lists/* && systemctl mask systemd-logind.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
