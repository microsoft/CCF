#!/bin/bash

HN=$(hostname)

if [ "$HN" == "ccf-ci-perf-0" ]; then
    echo "-n 10.0.0.8 -n 10.0.0.9 -n 10.0.0.10"
fi