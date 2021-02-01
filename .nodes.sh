#!/bin/bash

HN=$(hostname)

if [ "$HN" == "ccf-perf-uk-0" ]; then
    echo "-n ssh://10.1.0.7 -n ssh://10.1.0.4 -n ssh://10.1.0.5"
fi