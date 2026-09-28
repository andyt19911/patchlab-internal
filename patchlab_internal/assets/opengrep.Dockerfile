# PatchLab Internal's Opengrep engine image, built once per runner.
# The binary is Opengrep's pinned release, checked against the sha256 Caer pins for the same
# release (caer infra/images/opengrep); the build fails if the download differs.
# Scans run with --network none, read-only, on a copy of the checkout.
ARG BASE=alpine:3.23
FROM ${BASE}
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256
# The binary links libstdc++, libgcc and zlib. A runner that can't reach the Alpine
# package CDN builds on an Alpine-based image that already has them, with APK_PACKAGES="".
ARG APK_PACKAGES="libstdc++ libgcc zlib"
# A runner whose egress goes through a TLS-inspecting proxy gets its CA bundle
# bind-mounted for these downloads only (PatchLab adds the mounts); it never
# stays in the image.
RUN if [ -n "$APK_PACKAGES" ]; then apk add --no-cache $APK_PACKAGES; fi \
 && wget -qO /usr/local/bin/opengrep \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_musllinux_x86" \
 && echo "${OPENGREP_SHA256}  /usr/local/bin/opengrep" | sha256sum -c - \
 && chmod +x /usr/local/bin/opengrep \
 && opengrep --version
ENV HOME=/tmp
USER 65534:65534
ENTRYPOINT ["opengrep"]
