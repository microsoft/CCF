#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -ex

# Work-around for https://github.com/intel/linux-sgx/issues/395
mkdir -p /etc/init

echo "APT::Acquire::Retries \"5\";" | tee /etc/apt/apt.conf.d/80-retries

UBUNTU=focal
PSW_VERSION=2.17.100

if [ -z "$PSW_VERSION" ]; then 
    echo "Please set PSW_VERSION (e.g. 2.11)." >&2; 
    exit 1; 
fi

apt-get update && apt-get install -y wget gnupg

# Use the APT preference file to pin sgx packages to specific versions
# Reference https://manpages.debian.org/buster/apt/apt_preferences.5.en.html
# Download the pref file from https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/
# Assuming file name to follow *sgx_<PSW_VERSION>_${UBUNTU}_custom_version.cfg convention
wget -r -l1 --no-parent -nd -A "*sgx_${PSW_VERSION//./_}_${UBUNTU}_custom_version.cfg" "https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files"
mv ./*"sgx_${PSW_VERSION//./_}_${UBUNTU}_custom_version.cfg" "/etc/apt/preferences.d/intel-sgx.pref"