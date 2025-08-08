FROM mcr.microsoft.com/azurelinux/base/core:3.0 AS build

ARG PLATFORM
ARG CCF_VERSION

RUN tdnf update -y && tdnf install -y \
    ca-certificates \
    wget

# Install ccf runtime and its minimal dependencies into a staging location
# then copy into the final distroless image
RUN mkdir /staging \
    && wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${PLATFORM}_${CCF_VERSION}_x86_64.rpm -O run.rpm \
    && tdnf install -y --releasever=3.0 --installroot /staging run.rpm \
    && tdnf clean all \
    && rm -rf /staging/etc/tdnf \
    && rm -rf /staging/run/* \
    && rm -rf /staging/var/cache/tdnf \
    && find /staging/var/log -type f -size +0 -delete \
    && mv /staging/opt/ccf_${PLATFORM}/bin/cchost /staging/usr/bin/cchost 

FROM mcr.microsoft.com/azurelinux/distroless/minimal:3.0

ARG PLATFORM

COPY --from=build /staging/ .
