#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

# This script measures how long the recovery procedure takes.
# Note that the script makes uses of the sandbox and as such, 
# the timing results are rough (+/- a few seconds).

# Usage: $ cd CCF/build && ../tests/recovery_benchmark.sh /opt/ccf [--with-snapshot] [--sig-tx-interval 100] [--load-run-time-s 30]

if [ -z "$1" ]; then
    echo "Error: First argument should be CCF install path"
    exit 1
fi
ccf_install_path=$1
shift

with_snapshot=false
signature_tx_interval=10000 # CCF default
load_run_time_s=20

while [ "$1" != "" ]; do
    case $1 in
        --with-snapshot)
            with_snapshot=true
            ;;
        --sig-tx-interval)
            signature_tx_interval="$2"
            shift
            ;;
        --load-run-time-s)
            load_run_time_s="$2"
            shift
            ;;
        *)
            break
    esac
    shift
done

set -e

function service_http_status()
{
    curl -o /dev/null -s https://127.0.0.1:8000/commit -w "%{http_code}" --cacert ./workspace/sandbox_common/service_cert.pem
}

function current_ledger_length()
{
    curl -s https://127.0.0.1:8000/node/commit --cacert ./workspace/sandbox_common/service_cert.pem | jq '.transaction_id | split(".")[1] | tonumber'
}

function poll_for_service_open()
{
    network_live_time=$1
    sandbox_pid=$2
    polls=0
    while [ ! "$(service_http_status)" == "200" ] && [ "${polls}" -lt "${network_live_time}" ]; do
        echo "Waiting for service to open..."
        polls=$((polls+1))
        sleep 1
        if ! ps -p ${sandbox_pid} > /dev/null; then
            echo "Sandbox process has terminated"
            return 0
        fi
    done

    if [ "$(service_http_status)" == "200" ]; then
        return 1
    fi

    return 0
}

function cleanup() {
  kill "$(jobs -p)"
}
trap cleanup EXIT

if [ -n "$PYTHON_PACKAGE_PATH" ]; then
    PYTHON_PACKAGE_PATH=$(realpath -s "${PYTHON_PACKAGE_PATH}")
fi

echo "** Start original service"
"${ccf_install_path}"/bin/sandbox.sh --sig-tx-interval "${signature_tx_interval}" & 
sandbox_pid=$!

network_live_time=60
if poll_for_service_open ${network_live_time} ${sandbox_pid}; then
    echo "Error: Timeout waiting ${network_live_time}s for service to open"
    kill "$(jobs -p)"
    exit 1
fi

echo "** Load service"
python3.8 -m venv .recovery_bench_env
source .recovery_bench_env/bin/activate
python -m pip -q install locust

locust --headless --locustfile ../tests/infra/locust_file.py --ca ./workspace/sandbox_common/service_cert.pem --key ./workspace/sandbox_common/user0_privk.pem --cert ./workspace/sandbox_common/user0_cert.pem --spawn-rate 100 --users 100 --rate 1000000 --node-host https://127.0.0.1:8000 --host https://0.0.0.0 --run-time "${load_run_time_s}s"

entries_to_recover=$(current_ledger_length)

echo "** Stop service"
kill $sandbox_pid

echo "** Copy data from defunct service"
LEDGER_DIR="0.ledger/"
SNAPSHOTS_DIR="0.snapshots/"
rm -rf $LEDGER_DIR $SNAPSHOTS_DIR
cp -R ./workspace/sandbox_0/$LEDGER_DIR .
cp -R ./workspace/sandbox_0/$SNAPSHOTS_DIR .
recovery_snapshot_dir_args=""
if [ "$with_snapshot" = true ]; then 
    recovery_snapshot_dir_args="--snapshots-dir $SNAPSHOTS_DIR"
fi

echo "** Recover service"
seconds_before_recovery=$SECONDS
# shellcheck disable=SC2086
"${ccf_install_path}"/bin/sandbox.sh --recover --ledger-dir $LEDGER_DIR --common-dir ./workspace/sandbox_common --ledger-recovery-timeout 1000 ${recovery_snapshot_dir_args} &
sandbox_pid=$!
network_live_time=600
if poll_for_service_open ${network_live_time} ${sandbox_pid}; then
    echo "Error: Timeout waiting ${network_live_time}s for service to open"
    kill "$(jobs -p)"
    exit 1
fi

entries_final=$(current_ledger_length)
if [ "${entries_final}" -lt "${entries_to_recover}" ]; then
    echo "Error: not all entries were recovered (expected ${entries_to_recover} but only recovered ${entries_final})"
    exit 1
fi

total_recovery_time=$((SECONDS-seconds_before_recovery))
echo "** Successfully recovered ${entries_final} entries"

echo "Total recovery time: $total_recovery_time secs [# entries: ${entries_to_recover}, with snapshot: ${with_snapshot}, sig interval: ${signature_tx_interval}]"
