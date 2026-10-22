# syntax=docker/dockerfile:1
#
# Delta Sharing reference server, repackaged for amd64.
#
# WHY THIS FILE EXISTS. The upstream image
# deltaio/delta-sharing-server:0.7.5 is published for **arm64 only**
# (verified 2026-10-18: it has no `latest`, `1.0.0` or `1.0.2` tag at
# all, and 0.7.5/0.7.0 are single-manifest arm64). On an amd64 host it
# pulls without complaint, then exits immediately on start. That failure
# mode is worth recording: the image reference looks correct, `docker
# compose config` validates, and the breakage only appears at runtime as
# a container that will not stay up.
#
# The server itself is architecture-independent -- Scala/Java bytecode
# plus a shell launcher. So the first stage is used purely as a FILE
# SOURCE: we copy /opt/docker out of it and never execute anything from
# it. The runtime stage is a normal amd64 JRE.
#
# This is preferable to the alternatives for AC6 / T-12 reasons:
#   * Downloading the release zip from GitHub at build time would add a
#     network dependency to every rebuild, and pin to a URL rather than
#     to a content digest.
#   * Vendoring the jars into the repository would put ~100 MB of
#     binaries in git for no traceability gain.
#   * qemu/binfmt emulation is not installed here, and an emulated JVM
#     is a poor foundation for timing-sensitive gateway tests.
#
# Java 11 is chosen over the host's Java 21 on purpose: 0.7.5 predates
# 21, and the JPMS encapsulation tightening in 17+ breaks reflective
# access in the Hadoop filesystem layer this server depends on. (The
# HTTP layer is Armeria, not Jetty -- confirmed from the startup log
# during the 2026-10-18 smoke test.) Pinning the JRE in the image also
# means the host's JDK can be upgraded without silently changing the
# provider's runtime.

FROM --platform=linux/arm64 deltaio/delta-sharing-server:0.7.5 AS upstream

FROM eclipse-temurin:11-jre-jammy

# The uid the container will be run as must EXIST as a named user in the
# image, not merely be passed to `docker run --user`.
#
# This is not cosmetic. The server's filesystem layer is Hadoop, and
# Hadoop's UserGroupInformation performs an OS login before it opens a
# path. Running as a bare numeric uid with no /etc/passwd entry makes
# that lookup return a null name, and the failure surfaces as:
#
#   KerberosAuthException: failure to login:
#   LoginException: NullPointerException: invalid null input: name
#
# which the server then reports to the client as a bare
# HTTP 500 {"errorCode": "INTERNAL_ERROR", "message": ""}.
#
# Observed 2026-10-18: /shares and /schemas answered correctly because
# they are served from the config file in memory, while /tables and
# /query returned 500 because only those touch the filesystem. A config
# error would have broken all four. That asymmetry -- metadata fine,
# data access failing -- is the signature of this problem, and is worth
# remembering before blaming the table or the Delta protocol version.
#
# Default 1000 matches the usual first interactive user on Ubuntu, which
# is what bind-mounted 0600 files in _secrets/ are owned by. Override at
# build time if the host differs:
#     docker compose build --build-arg APP_UID=$(id -u) \
#                          --build-arg APP_GID=$(id -g) delta_sharing_server
ARG APP_UID=1000
ARG APP_GID=1000
RUN if ! getent group "${APP_GID}" >/dev/null; then \
        groupadd -g "${APP_GID}" provider; \
    fi \
    && if ! getent passwd "${APP_UID}" >/dev/null; then \
        useradd -u "${APP_UID}" -g "${APP_GID}" -M -d /home/provider -s /usr/sbin/nologin provider; \
    fi \
    && mkdir -p /home/provider \
    && chown "${APP_UID}:${APP_GID}" /home/provider

# Belt and braces. Hadoop consults HADOOP_USER_NAME before falling back
# to an OS login, so this short-circuits the lookup even if the image is
# ever run as a uid that was not baked in above.
ENV HADOOP_USER_NAME=provider \
    HOME=/home/provider

# Copy the packaged application only. /opt/docker holds bin/ (launcher
# scripts), lib/ (jars) and conf/. All of it is bytecode or shell.
COPY --from=upstream /opt/docker /opt/docker

# Hadoop configuration, so the server's S3A client aims at the local
# MinIO service rather than at AWS. /opt/docker/conf is the LAST entry on
# the launcher's app_classpath ($lib_dir/../conf), which is how Hadoop
# finds this. Copied at build time rather than bind-mounted so that a
# T-12 rebuild from code cannot omit it -- without this file the server
# signs URLs against s3.amazonaws.com for data that lives in MinIO, and
# the only visible symptom is a 403 at the consumer.
COPY core-site.xml /opt/docker/conf/core-site.xml

# The upstream image runs as uid 1001; compose runs this as the host
# user instead so that a 0600 config bind-mounted from _secrets/ is
# readable. Make the application tree readable and executable by any
# uid so that override cannot fail on permissions.
RUN chmod -R a+rX /opt/docker \
    && chmod a+x /opt/docker/bin/* \
    && mkdir -p /data /config \
    && chmod 755 /data /config

EXPOSE 8080

# sbt-native-packager launcher. Callers must pass a bare `--` before
# application arguments, or `--config` is parsed as a JVM option and the
# process exits. docker-compose.yml does this; keep it if you change the
# command.
ENTRYPOINT ["/opt/docker/bin/delta-sharing-server"]
