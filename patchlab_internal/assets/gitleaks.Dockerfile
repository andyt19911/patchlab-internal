# PatchLab Internal's gitleaks image, built once per runner. The Go module proxy and
# checksum database verify the source; the binary is static and runs from scratch,
# with --network none, read-only, on a copy of the checkout.
ARG GO_IMAGE=golang:1.26-bookworm
FROM ${GO_IMAGE} AS build
ARG GITLEAKS_VERSION
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}

FROM scratch
COPY --from=build /out/gitleaks /gitleaks
USER 65534:65534
ENTRYPOINT ["/gitleaks"]
