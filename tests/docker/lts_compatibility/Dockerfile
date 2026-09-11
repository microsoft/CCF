ARG BASE_IMAGE
FROM ${BASE_IMAGE}

RUN if command -v tdnf >/dev/null 2>&1; then \
      tdnf -y update && \
      tdnf -y install \
        ca-certificates \
        curl-devel \
        libuv-devel \
        nghttp2-devel \
        openssl-devel && \
      tdnf clean all; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf -y update && \
      dnf -y install \
        ca-certificates \
        libcurl-devel \
        libnghttp2-devel \
        libstdc++-devel \
        libuv-devel \
        openssl-devel && \
      dnf clean all; \
    else \
      echo "Unsupported base image: expected tdnf or dnf" >&2; \
      exit 1; \
    fi

COPY opt/ccf /opt/ccf

ENV LD_LIBRARY_PATH=/opt/ccf/lib
ENV PATH=/opt/ccf/bin:${PATH}
