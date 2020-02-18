#!/bin/bash

HN=$(hostname)

if [ "$HN" == "ccf-ci-5" ]; then
    echo "-n 10.0.0.6 -n 10.0.0.8 -n 10.0.0.11"
elif [ "$HN" == "ccf-ci-9" ]; then
    echo "-n 10.0.0.13 -n 10.0.0.14 -n 10.0.0.15"
fi