# Copyright © 2020 Pennock Tech, LLC.
# All rights reserved, except as granted under license.
# Licensed per file LICENSE.txt

# Maintainer note: also consider bumping CircleCI image versions
ARG BUILDER_IMAGE="golang:1.14.5"
ARG RUNTIME_BASE_IMAGE="scratch"
ARG PORT=1079

# =============================8< Builder >8==============================

FROM ${BUILDER_IMAGE} AS builder

WORKDIR /go/src/fingerd
COPY . .

# If not in main, we might use: namespaceStr="$(go list -f '{{.ImportPath}}' .)"
RUN versionStr="$(git describe --tags --always --dirty)" && \
	CGO_ENABLED=0 GOOS=linux \
		go build \
		-tags "docker" \
		-ldflags "-s -X main.fingerVersion=$versionStr" \
		.

# ===========================8< Final Image >8============================

FROM ${RUNTIME_BASE_IMAGE}
ARG PORT
ENV PORT=${PORT}

COPY --from=builder /go/src/fingerd/fingerd /bin/fingerd

# By convention, nobody:nogroup should be -2:-2 but Docker rejects that,
# demanding positive integers.  On a Linux system I checked, they're actually
# 16-bit -2 in a 32-bit field.  So 65534:65534
USER 65534:65534
ENTRYPOINT ["/bin/fingerd"]
CMD ["-log.json", "-alias-file=", "--listen-env=PORT"]
EXPOSE ${PORT}
VOLUME ["/home"]

ARG BUILDER_IMAGE
ARG RUNTIME_BASE_IMAGE
LABEL maintainer="noc+fingerd@pennock-tech.com"
LABEL tech.pennock.builder.image="${BUILDER_IMAGE}"
LABEL tech.pennock.baseimage="${RUNTIME_BASE_IMAGE}"
LABEL tech.pennock.portlist="${PORT}"

# <https://github.com/opencontainers/image-spec/blob/master/annotations.md>
# nb: we'd need the caller to pass in the version as a build-arg to have
# it sanely capturable here.
LABEL org.opencontainers.image.source="https://go.pennock.tech/fingerd/"
LABEL org.opencontainers.image.vendor="Pennock Tech, LLC"
LABEL org.opencontainers.image.title="fingerd"
LABEL org.opencontainers.image.description="Security-focused golang finger daemon"
LABEL org.opencontainers.image.licenses="MIT"
