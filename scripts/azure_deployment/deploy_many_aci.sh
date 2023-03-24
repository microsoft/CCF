#!/bin/bash

set -e

deployment_name="northeurope-mariner-confidential"

for ITER in {1..3}; do
    echo "Deploying..."
    SECONDS=0
    date
    python3.8 arm_template.py deploy aci --subscription-id 12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730 --resource-group ccf-aci --region northeurope --deployment-name "julien-test-${deployment_name}-${ITER}" --aci-image mcr.microsoft.com/cbl-mariner/base/core:2.0 --ports 8080 --count 1 
    DURATION_IN_SECONDS=$SECONDS
    echo "Deployed in ${DURATION_IN_SECONDS}s"
done