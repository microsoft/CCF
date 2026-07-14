#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -euo pipefail

readonly SSHD=/usr/sbin/sshd
readonly PID_FILE=/run/sshd.pid
readonly LOG_FILE=/tmp/sshd-codespaces.log
readonly CONFIG_DIR=/etc/ssh/sshd_config.d
readonly CONFIG_FILE=${CONFIG_DIR}/00-codespaces.conf
readonly SSHD_OPTIONS=(
  -p 22
  -o "PidFile=${PID_FILE}"
  -o PermitRootLogin=prohibit-password
  -o PasswordAuthentication=no
  -o PubkeyAuthentication=yes
)

sshd_is_running()
{
  [[ -s "${PID_FILE}" ]] || return 1

  local pid
  pid=$(<"${PID_FILE}")
  [[ "${pid}" =~ ^[0-9]+$ ]] && [[ -r "/proc/${pid}/comm" ]] &&
    [[ "$(<"/proc/${pid}/comm")" == "sshd" ]]
}

if ! sshd_is_running; then
  if [[ -f "${PID_FILE}" ]]; then
    rm -f "${PID_FILE}"
  fi

  install -d -m 0755 "${CONFIG_DIR}" /run/sshd
  if ! grep -Fqx "Include ${CONFIG_DIR}/*.conf" /etc/ssh/sshd_config; then
    sed -i "1iInclude ${CONFIG_DIR}/*.conf" /etc/ssh/sshd_config
  fi
  printf '%s\n' \
    "PermitRootLogin prohibit-password" \
    "PasswordAuthentication no" \
    "PubkeyAuthentication yes" >"${CONFIG_FILE}"
  ssh-keygen -A

  "${SSHD}" -t "${SSHD_OPTIONS[@]}"
  "${SSHD}" "${SSHD_OPTIONS[@]}" -E "${LOG_FILE}"

  for _ in {1..50}; do
    if sshd_is_running; then
      break
    fi
    sleep 0.1
  done

  if ! sshd_is_running; then
    echo "sshd did not start; see ${LOG_FILE}" >&2
    exit 1
  fi
fi

exec "$@"
