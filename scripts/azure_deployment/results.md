# Results from ACI deployment tests

Image: mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-snp for confidential SKU (856MB) and mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-virtual for non-confidential SKU (931MB)
Script used: deploy_many_aci.sh

Note: CCF startup times accounts for about 5s.

# North Europe (not cached):

## Confidential

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-northeurope-virtual-confidential-1-0/overview

Times:
- Pulling image 11secs after deployment starts, 
- Image pull: 25 secs first, then 15 secs.
- Container started 57 to 146 secs (!!!) seconds after pull is complete.
- Deployment succeeded 25 seconds after container is started.

Template: 
```json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "containerGroups_julien_test_north_europe_confidential_1_0_name": {
            "defaultValue": "julien-test-north-europe-confidential-1-0",
            "type": "String"
        }
    },
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.ContainerInstance/containerGroups",
            "apiVersion": "2022-10-01-preview",
            "name": "[parameters('containerGroups_julien_test_north_europe_confidential_1_0_name')]",
            "location": "northeurope",
            "properties": {
                "sku": "Confidential",
                "confidentialComputeProperties": {
                    "ccePolicy": "cGFja2FnZSBwb2xpY3kKCmFwaV9zdm4gOj0gIjAuMTAuMCIKCm1vdW50X2RldmljZSA6PSB7ImFsbG93ZWQiOiB0cnVlfQptb3VudF9vdmVybGF5IDo9IHsiYWxsb3dlZCI6IHRydWV9CmNyZWF0ZV9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZSwgImVudl9saXN0IjogbnVsbCwgImFsbG93X3N0ZGlvX2FjY2VzcyI6IHRydWV9CnVubW91bnRfZGV2aWNlIDo9IHsiYWxsb3dlZCI6IHRydWV9IAp1bm1vdW50X292ZXJsYXkgOj0geyJhbGxvd2VkIjogdHJ1ZX0KZXhlY19pbl9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZSwgImVudl9saXN0IjogbnVsbH0KZXhlY19leHRlcm5hbCA6PSB7ImFsbG93ZWQiOiB0cnVlLCAiZW52X2xpc3QiOiBudWxsLCAiYWxsb3dfc3RkaW9fYWNjZXNzIjogdHJ1ZX0Kc2h1dGRvd25fY29udGFpbmVyIDo9IHsiYWxsb3dlZCI6IHRydWV9CnNpZ25hbF9jb250YWluZXJfcHJvY2VzcyA6PSB7ImFsbG93ZWQiOiB0cnVlfQpwbGFuOV9tb3VudCA6PSB7ImFsbG93ZWQiOiB0cnVlfQpwbGFuOV91bm1vdW50IDo9IHsiYWxsb3dlZCI6IHRydWV9CmdldF9wcm9wZXJ0aWVzIDo9IHsiYWxsb3dlZCI6IHRydWV9CmR1bXBfc3RhY2tzIDo9IHsiYWxsb3dlZCI6IHRydWV9CnJ1bnRpbWVfbG9nZ2luZyA6PSB7ImFsbG93ZWQiOiB0cnVlfQpsb2FkX2ZyYWdtZW50IDo9IHsiYWxsb3dlZCI6IHRydWV9CnNjcmF0Y2hfbW91bnQgOj0geyJhbGxvd2VkIjogdHJ1ZX0Kc2NyYXRjaF91bm1vdW50IDo9IHsiYWxsb3dlZCI6IHRydWV9Cg=="
                },
                "containers": [
                    {
                        "name": "[parameters('containerGroups_julien_test_north_europe_confidential_1_0_name')]",
                        "properties": {
                            "image": "mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-snp",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "openssl ecparam -out member0_privk.pem -name secp384r1 -genkey && openssl req -new -key member0_privk.pem -x509 -nodes -days 365 -out member0_cert.pem -sha384 -subj=/CN=member0 && openssl genrsa -out member0_enc_privk.pem 2048 && openssl rsa -in member0_enc_privk.pem -pubout -out member0_enc_pubk.pem && echo 'eyJlbmNsYXZlIjogeyJmaWxlIjogIi91c3IvbGliL2NjZi9saWJqc19nZW5lcmljLnNucC5zbyIsICJwbGF0Zm9ybSI6ICJTTlAiLCAidHlwZSI6ICJSZWxlYXNlIn0sICJuZXR3b3JrIjogeyJub2RlX3RvX25vZGVfaW50ZXJmYWNlIjogeyJiaW5kX2FkZHJlc3MiOiAiMTI3LjAuMC4xOjgwODEifSwgInJwY19pbnRlcmZhY2VzIjogeyJpbnRlcmZhY2VfbmFtZSI6IHsiYmluZF9hZGRyZXNzIjogIjAuMC4wLjA6ODA4MCJ9fX0sICJjb21tYW5kIjogeyJ0eXBlIjogIlN0YXJ0IiwgInN0YXJ0IjogeyJjb25zdGl0dXRpb25fZmlsZXMiOiBbXSwgIm1lbWJlcnMiOiBbeyJjZXJ0aWZpY2F0ZV9maWxlIjogIm1lbWJlcjBfY2VydC5wZW0iLCAiZW5jcnlwdGlvbl9wdWJsaWNfa2V5X2ZpbGUiOiAibWVtYmVyMF9lbmNfcHViay5wZW0ifV19fSwgImF0dGVzdGF0aW9uIjogeyJzbnBfZW5kb3JzZW1lbnRzX3NlcnZlcnMiOiBbeyJ0eXBlIjogIkFNRCIsICJ1cmwiOiAia2RzaW50Zi5hbWQuY29tIn1dfX0=' | base64 -d > config.json && cchost --config config.json"
                            ],
                            "ports": [
                                {
                                    "protocol": "TCP",
                                    "port": 8080
                                }
                            ],
                            "environmentVariables": [],
                            "resources": {
                                "requests": {
                                    "memoryInGB": 16,
                                    "cpu": 4
                                }
                            }
                        }
                    }
                ],
                "initContainers": [],
                "restartPolicy": "Never",
                "ipAddress": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 8080
                        }
                    ],
                    "ip": "52.142.88.255",
                    "type": "Public"
                },
                "osType": "Linux"
            }
        }
    ]
}
```

## Non-confidential

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-northeurope-virtual-non-confidential-1-0/overview

Times:
- Pulling image 11-15secs after deployment starts, 
- Image pull: 25 secs first, then 15 secs.
- Container started 11 seconds after pull is complete.
- Deployment succeeded 25 seconds after container is started.

Template:
```json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "containerGroups_julien_test_northeurope_non_confidential_1_0_name": {
            "defaultValue": "julien-test-northeurope-non-confidential-1-0",
            "type": "String"
        }
    },
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.ContainerInstance/containerGroups",
            "apiVersion": "2022-10-01-preview",
            "name": "[parameters('containerGroups_julien_test_northeurope_non_confidential_1_0_name')]",
            "location": "northeurope",
            "properties": {
                "sku": "Standard",
                "containers": [
                    {
                        "name": "[parameters('containerGroups_julien_test_northeurope_non_confidential_1_0_name')]",
                        "properties": {
                            "image": "mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-virtual",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "openssl ecparam -out member0_privk.pem -name secp384r1 -genkey && openssl req -new -key member0_privk.pem -x509 -nodes -days 365 -out member0_cert.pem -sha384 -subj=/CN=member0 && openssl genrsa -out member0_enc_privk.pem 2048 && openssl rsa -in member0_enc_privk.pem -pubout -out member0_enc_pubk.pem && echo 'eyJlbmNsYXZlIjogeyJmaWxlIjogIi91c3IvbGliL2NjZi9saWJqc19nZW5lcmljLnZpcnR1YWwuc28iLCAicGxhdGZvcm0iOiAiVmlydHVhbCIsICJ0eXBlIjogIlJlbGVhc2UifSwgIm5ldHdvcmsiOiB7Im5vZGVfdG9fbm9kZV9pbnRlcmZhY2UiOiB7ImJpbmRfYWRkcmVzcyI6ICIxMjcuMC4wLjE6ODA4MSJ9LCAicnBjX2ludGVyZmFjZXMiOiB7ImludGVyZmFjZV9uYW1lIjogeyJiaW5kX2FkZHJlc3MiOiAiMC4wLjAuMDo4MDgwIn19fSwgImNvbW1hbmQiOiB7InR5cGUiOiAiU3RhcnQiLCAic3RhcnQiOiB7ImNvbnN0aXR1dGlvbl9maWxlcyI6IFtdLCAibWVtYmVycyI6IFt7ImNlcnRpZmljYXRlX2ZpbGUiOiAibWVtYmVyMF9jZXJ0LnBlbSIsICJlbmNyeXB0aW9uX3B1YmxpY19rZXlfZmlsZSI6ICJtZW1iZXIwX2VuY19wdWJrLnBlbSJ9XX19LCAiYXR0ZXN0YXRpb24iOiB7InNucF9lbmRvcnNlbWVudHNfc2VydmVycyI6IFt7InR5cGUiOiAiQU1EIiwgInVybCI6ICJrZHNpbnRmLmFtZC5jb20ifV19fQ==' | base64 -d > config.json && cchost --config config.json"
                            ],
                            "ports": [
                                {
                                    "protocol": "TCP",
                                    "port": 8080
                                }
                            ],
                            "environmentVariables": [],
                            "resources": {
                                "requests": {
                                    "memoryInGB": 16,
                                    "cpu": 4
                                }
                            }
                        }
                    }
                ],
                "initContainers": [],
                "restartPolicy": "Never",
                "ipAddress": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 8080
                        }
                    ],
                    "ip": "20.234.74.9",
                    "type": "Public"
                },
                "osType": "Linux"
            }
        }
    ]
}

```

# EastUs2euap:

## Confidential (cached)

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-eastus2euap-virtual-confidential-1-0/overview


Times:
- Pulling image 11secs after deployment starts, 
- Image pull: 0 (we confirm that image has been cached there)
- Container started 45 (twice) to 155 secs (!!!) seconds after pull is complete. (Q: Why is is it variable?)
- Deployment succeeded 20 seconds after container is started.

Template:
```json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "containerGroups_julien_test_eastus2euap_confidential_1_0_name": {
            "defaultValue": "julien-test-eastus2euap-confidential-1-0",
            "type": "String"
        }
    },
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.ContainerInstance/containerGroups",
            "apiVersion": "2022-10-01-preview",
            "name": "[parameters('containerGroups_julien_test_eastus2euap_confidential_1_0_name')]",
            "location": "eastus2euap",
            "properties": {
                "sku": "Confidential",
                "confidentialComputeProperties": {
                    "ccePolicy": "cGFja2FnZSBwb2xpY3kKCmFwaV9zdm4gOj0gIjAuMTAuMCIKCm1vdW50X2RldmljZSA6PSB7ImFsbG93ZWQiOiB0cnVlfQptb3VudF9vdmVybGF5IDo9IHsiYWxsb3dlZCI6IHRydWV9CmNyZWF0ZV9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZSwgImVudl9saXN0IjogbnVsbCwgImFsbG93X3N0ZGlvX2FjY2VzcyI6IHRydWV9CnVubW91bnRfZGV2aWNlIDo9IHsiYWxsb3dlZCI6IHRydWV9IAp1bm1vdW50X292ZXJsYXkgOj0geyJhbGxvd2VkIjogdHJ1ZX0KZXhlY19pbl9jb250YWluZXIgOj0geyJhbGxvd2VkIjogdHJ1ZSwgImVudl9saXN0IjogbnVsbH0KZXhlY19leHRlcm5hbCA6PSB7ImFsbG93ZWQiOiB0cnVlLCAiZW52X2xpc3QiOiBudWxsLCAiYWxsb3dfc3RkaW9fYWNjZXNzIjogdHJ1ZX0Kc2h1dGRvd25fY29udGFpbmVyIDo9IHsiYWxsb3dlZCI6IHRydWV9CnNpZ25hbF9jb250YWluZXJfcHJvY2VzcyA6PSB7ImFsbG93ZWQiOiB0cnVlfQpwbGFuOV9tb3VudCA6PSB7ImFsbG93ZWQiOiB0cnVlfQpwbGFuOV91bm1vdW50IDo9IHsiYWxsb3dlZCI6IHRydWV9CmdldF9wcm9wZXJ0aWVzIDo9IHsiYWxsb3dlZCI6IHRydWV9CmR1bXBfc3RhY2tzIDo9IHsiYWxsb3dlZCI6IHRydWV9CnJ1bnRpbWVfbG9nZ2luZyA6PSB7ImFsbG93ZWQiOiB0cnVlfQpsb2FkX2ZyYWdtZW50IDo9IHsiYWxsb3dlZCI6IHRydWV9CnNjcmF0Y2hfbW91bnQgOj0geyJhbGxvd2VkIjogdHJ1ZX0Kc2NyYXRjaF91bm1vdW50IDo9IHsiYWxsb3dlZCI6IHRydWV9Cg=="
                },
                "containers": [
                    {
                        "name": "[parameters('containerGroups_julien_test_eastus2euap_confidential_1_0_name')]",
                        "properties": {
                            "image": "mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-snp",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "openssl ecparam -out member0_privk.pem -name secp384r1 -genkey && openssl req -new -key member0_privk.pem -x509 -nodes -days 365 -out member0_cert.pem -sha384 -subj=/CN=member0 && openssl genrsa -out member0_enc_privk.pem 2048 && openssl rsa -in member0_enc_privk.pem -pubout -out member0_enc_pubk.pem && echo 'eyJlbmNsYXZlIjogeyJmaWxlIjogIi91c3IvbGliL2NjZi9saWJqc19nZW5lcmljLnNucC5zbyIsICJwbGF0Zm9ybSI6ICJTTlAiLCAidHlwZSI6ICJSZWxlYXNlIn0sICJuZXR3b3JrIjogeyJub2RlX3RvX25vZGVfaW50ZXJmYWNlIjogeyJiaW5kX2FkZHJlc3MiOiAiMTI3LjAuMC4xOjgwODEifSwgInJwY19pbnRlcmZhY2VzIjogeyJpbnRlcmZhY2VfbmFtZSI6IHsiYmluZF9hZGRyZXNzIjogIjAuMC4wLjA6ODA4MCJ9fX0sICJjb21tYW5kIjogeyJ0eXBlIjogIlN0YXJ0IiwgInN0YXJ0IjogeyJjb25zdGl0dXRpb25fZmlsZXMiOiBbXSwgIm1lbWJlcnMiOiBbeyJjZXJ0aWZpY2F0ZV9maWxlIjogIm1lbWJlcjBfY2VydC5wZW0iLCAiZW5jcnlwdGlvbl9wdWJsaWNfa2V5X2ZpbGUiOiAibWVtYmVyMF9lbmNfcHViay5wZW0ifV19fSwgImF0dGVzdGF0aW9uIjogeyJzbnBfZW5kb3JzZW1lbnRzX3NlcnZlcnMiOiBbeyJ0eXBlIjogIkFNRCIsICJ1cmwiOiAia2RzaW50Zi5hbWQuY29tIn1dfX0=' | base64 -d > config.json && cchost --config config.json"
                            ],
                            "ports": [
                                {
                                    "protocol": "TCP",
                                    "port": 8080
                                }
                            ],
                            "environmentVariables": [],
                            "resources": {
                                "requests": {
                                    "memoryInGB": 16,
                                    "cpu": 4
                                }
                            }
                        }
                    }
                ],
                "initContainers": [],
                "restartPolicy": "Never",
                "ipAddress": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 8080
                        }
                    ],
                    "ip": "20.47.178.242",
                    "type": "Public"
                },
                "osType": "Linux"
            }
        }
    ]
}
```

## Non-confidential (not cached)

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-eastus2euap-virtual-confidential-1-0/overview

Times:
- Pulling image 11secs after deployment starts, 
- Image pull: 17 secs.
- Container started 8 secs after pull is complete (eastus2euap is fast!)
- Deployment succeeded 25 seconds after container is started.

# Mariner (north europe)

## Confidential

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-northeurope-mariner-confidential-1-0   

Times:
- Pulling image 12secs after deployment starts, 
- Image pull: 3 secs
- Container started 40 secs after pull is complete :(
- Deployment succeeded after 75 secs.

## Non-confidential

Image: mcr.microsoft.com/cbl-mariner/base/core:2.0  (66.7MB)

Link to deployment: https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/12f7cac3-b4c7-45c0-ba6a-f6cf93e8d730/resourceGroups/ccf-aci/providers/Microsoft.ContainerInstance/containerGroups/julien-test-northeurope-mariner-non-confidential-1-0

Template:
```json
{
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "containerGroups_julien_test_northeurope_mariner_non_confidential_1_0_name": {
            "defaultValue": "julien-test-northeurope-mariner-non-confidential-1-0",
            "type": "String"
        }
    },
    "variables": {},
    "resources": [
        {
            "type": "Microsoft.ContainerInstance/containerGroups",
            "apiVersion": "2022-10-01-preview",
            "name": "[parameters('containerGroups_julien_test_northeurope_mariner_non_confidential_1_0_name')]",
            "location": "northeurope",
            "properties": {
                "sku": "Standard",
                "containers": [
                    {
                        "name": "[parameters('containerGroups_julien_test_northeurope_mariner_non_confidential_1_0_name')]",
                        "properties": {
                            "image": "mcr.microsoft.com/cbl-mariner/base/core:2.0",
                            "command": [
                                "/bin/sh",
                                "-c",
                                "tail -f /dev/null"
                            ],
                            "ports": [
                                {
                                    "protocol": "TCP",
                                    "port": 8080
                                }
                            ],
                            "environmentVariables": [],
                            "resources": {
                                "requests": {
                                    "memoryInGB": 16,
                                    "cpu": 4
                                }
                            }
                        }
                    }
                ],
                "initContainers": [],
                "restartPolicy": "Never",
                "ipAddress": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": 8080
                        }
                    ],
                    "ip": "20.105.97.149",
                    "type": "Public"
                },
                "osType": "Linux"
            }
        }
    ]
}
```

Times:
- Pulling image 13-15secs after deployment starts, 
- Image pull: 2 secs
- Container started 24 secs after pull is complete
- Deployment succeeded after 42 secs


Summary:
- We confirm that we can observe that eastus2euap has successfully cached mcr.microsoft.com/ccf/app/run-js:4.0.0-dev5-snp :), shaving off 16 secs of deployment time. Chart: no green on "Eastus2euap CCF (conf: yes)" colum.
- Azure Python SDK marks deployments as successful about 20 seconds after the container has started - so we can improve here by tweaking the way we detect a deployment as complete. Chart: we can remove yellow on all columns.
- eastus2euap seems to be a little bit faster (30% reduction) to start containers. Is it expected or simply due to measurement variance? Chart: Blue bars are smaller for eastus2euap compared to north europe, for both confidential and non-confidential.
- Confidential SKU introduces a large overhead to container startup time: about 30 seconds fixed size and then 0.2 secs per MB. Chart: Blue bars are much larger for confidential SKU.