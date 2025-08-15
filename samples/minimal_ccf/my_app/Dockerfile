ARG CCF_RUNTIME_IMAGE

FROM mcr.microsoft.com/azurelinux/base/core:3.0 AS build

ARG PLATFORM
ARG MYAPP_VERSION

RUN tdnf update -y && tdnf install -y \
    ca-certificates \
    wget

RUN mkdir -p /tmp/devel && cd /tmp/devel && \
    wget https://github.com/microsoft/CCF/releases/download/ccf-${MYAPP_VERSION}/ccf_${PLATFORM}_devel_${MYAPP_VERSION}_x86_64.rpm -O devel.rpm && \
    tdnf install -y devel.rpm 

# Use CCF minimal runtime image as base for the final image
FROM ${CCF_RUNTIME_IMAGE}

ARG PLATFORM

COPY --from=build /opt/ccf_${PLATFORM}/lib/libjs_generic.${PLATFORM}.so /opt/ccf_${PLATFORM}/lib/libjs_generic.${PLATFORM}.so
