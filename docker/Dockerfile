FROM ubuntu:18.04

RUN echo "APT::Acquire::Retries \"5\";" | tee /etc/apt/apt.conf.d/80-retries

# Work-around for https://github.com/intel/linux-sgx/issues/395
RUN mkdir -p /etc/init

COPY getting_started/setup_vm/ /setup_vm/
RUN apt update \
    && apt install -y ansible software-properties-common bsdmainutils dnsutils \
    && cd setup_vm \
    && ansible-playbook ccf-dependencies-no-driver.yml ci-dependencies.yml \
    && rm -rf /tmp/* \
    && apt remove -y ansible software-properties-common \
    && apt -y autoremove \
    && apt -y clean
