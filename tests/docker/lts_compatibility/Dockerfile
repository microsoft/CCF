ARG BASE_IMAGE
FROM ${BASE_IMAGE}

RUN . /etc/os-release && \
    case "$VERSION_ID" in \
      3.0) \
        tdnf -y update && \
        tdnf -y install \
          ca-certificates \
          curl \
          libstdc++ \
          libuv \
          nghttp2 \
          openssl && \
        tdnf clean all \
        ;; \
      4.0) \
        dnf -y update && \
        dnf -y install --allowerasing \
          ca-certificates \
          libcurl \
          libstdc++ \
          libuv \
          openssl && \
        dnf clean all \
        ;; \
      *) \
        echo "Unsupported Azure Linux version: $VERSION_ID" >&2; \
        exit 1 \
        ;; \
    esac

# Path of the install tree within the build context. Releases before 7.0 install
# to a platform-specific directory, such as opt/ccf_virtual.
ARG INSTALL_DIR=opt/ccf
COPY ${INSTALL_DIR} /opt/ccf

ENV LD_LIBRARY_PATH=/opt/ccf/lib
ENV PATH=/opt/ccf/bin:${PATH}
