Using Member Keys Stored in HSM
===============================

This page explains how members' identity certificates and encryption keys stored in an `HSM <https://en.wikipedia.org/wiki/Hardware_security_module>`_ can be used with CCF. The following guide describes the usage of `Azure Key Vault <https://azure.microsoft.com/en-gb/products/key-vault/>`_

.. note::

    It is assumed that CCF members already have access to an existing Premium-tier Azure Key Vault, which is required for HSM-protected keys. See `these instructions <https://learn.microsoft.com/en-us/azure/key-vault/general/quick-create-portal#create-a-vault>`_ for more details on how to create one. Using the `Azure CLI <https://learn.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest>`_, it is possible to check the list of available Key Vault instances:

    .. code-block:: bash

        $ az keyvault list
        # Outputs list of available vaults, including name
        $ export VAULT_NAME="<vault_name>"

Certificate and Key Generation
------------------------------

Members' identity certificates should be generated on the `secp384r1` elliptic curve, using the `az keyvault certificate create <https://learn.microsoft.com/en-us/cli/azure/keyvault/certificate?view=azure-cli-latest#az-keyvault-certificate-create>`_ command, with the following ``akv_identity_cert_policy.json`` policy:

.. include:: akv_identity_cert_policy.json
    :literal:

.. code-block:: bash

    $ export IDENTITY_CERT_NAME="<identity-cert-name>"
    $ az keyvault certificate create --vault-name $VAULT_NAME -n $IDENTITY_CERT_NAME -p @akv_identity_cert_policy.json
    # Outputs certificate details

    # Corresponding private key is accessible at the same URL (substituting /certificate/ with /key/)
    $ az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Outputs key information, including kid url

Members' encryption keys should be RSA 2048 keys, generated with the `az keyvault key create <https://learn.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest#az-keyvault-key-create>`_ command:

.. code-block:: bash

    $ export ENCRYPTION_KEY_NAME="<encryption-key-name>"
    $ az keyvault key create --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --kty RSA-HSM --ops decrypt
    # Outputs key details, including kid url

The identity certificate and public encryption key can be downloaded to a PEM file and be passed on to members to be registered in a CCF service as a trusted member identity (see :ref:`governance/adding_member:Registering a New Member`). Alternatively, if the service has not yet been started, the public member identity can be passed on to operators and registered via the ``command.start.members`` configuration entry (see :ref:`operations/start_network:Starting the First Node`):

.. code-block:: bash

    $ az keyvault certificate download --file $IDENTITY_CERT_NAME.pem --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Downloads PEM identity certificate

    $ az keyvault key download --file $ENCRYPTION_KEY_NAME.pem --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME
    # Downloads PEM encryption public key

Signing Governance Requests
---------------------------

The following example uses the `Key Vault REST API <https://learn.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign>`_ to sign. To do so, it is necessary to create a service principal that will be used for authentication:

.. code-block:: bash

    $ export SP_NAME="<sp-name>"
    $ az ad sp create-for-rbac --name $SP_NAME
    # Returns client id (appId), client secret (password)

.. note:: To retrieve the service principal credentials after its creation, the credentials should be refreshed:

    .. code-block:: bash

        $ az ad sp credential reset --name <app_id>
        # Returns client id (appId), updated client secret (password)

Once created, the service principal should be granted the "Sign" key permission using the vault's configured authorization model.

Then, the following command should be run to retrieve an access token, replacing the values for ``<appid>``, ``<password>`` and ``<tenant>`` with the service principal credentials:

.. code-block:: bash

    export AZ_TOKEN=$(curl -X POST -d "grant_type=client_credentials&client_id=<appid>&client_secret=<password>&resource=https://vault.azure.net" https://login.microsoftonline.com/<tenant>/oauth2/token | jq -r .access_token)

The member's identity key is now ready to be used for signing governance requests.

COSE Signing
~~~~~~~~~~~~

.. note:: The `ccf_cose_sign1*` scripts are distributed in the `ccf` Python package, available on PyPI. It can be installed with `pip install ccf`.

As an alternative to the ``ccf_cose_sign1`` script when signing offline, CCF provides the ``ccf_cose_sign1_prepare`` and ``ccf_cose_sign1_finish`` scripts.

``ccf_cose_sign1_prepare`` takes the same arguments as ``ccf_cose_sign1``, minus the signing key, to produce a payload that can be sent to AKV:

.. code-block:: bash

    # Retrieve the digest to be signed
    $ export CREATED_AT=`date -uIs`
    $ ccf_cose_sign1_prepare --ccf-gov-msg-type proposal --ccf-gov-msg-created_at $CREATED_AT --content proposal.json --signing-cert $IDENTITY_CERT_NAME.pem > tbs
    $ cat tbs
    {"alg": "ES384", "value": "dUDKb1pqdi22R3gojLDiK4chPG5it3IaHxNbsuO3APIhlvo7pa16BX7miGPzx7Sy"} # To be signed by AKV

    # Retrieve the kid url for the identity key
    $ export IDENTITY_AKV_KID=$(az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME --query key.kid --output tsv)

    # Send the digest to the key management service for signing 
    $ curl -s -X POST $IDENTITY_AKV_KID/sign?api-version=7.1 --data @tbs -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" > signature

Finally, COSE Sign1 payload can be assembled with ``ccf_cose_sign1_finish``:

.. code-block:: bash

    $ ccf_cose_sign1_finish \
      --ccf-gov-msg-type proposal \
      --ccf-gov-msg-created_at $CREATED_AT \
      --content proposal.json \
      --signing-cert $IDENTITY_CERT_NAME.pem \
      --signature signature > cose_sign1

Like ``ccf_cose_sign1``, the output can be sent directly to the service via curl:

.. code-block:: bash

    $ ccf_cose_sign1_finish \
      --ccf-gov-msg-type proposal \
      --ccf-gov-msg-created_at $CREATED_AT \
      --content proposal.json \
      --signing-cert $IDENTITY_CERT_NAME.pem \
      --signature signature \
    | curl https://<ccf-node-address>/gov/members/proposals:create?api-version=2024-07-01 \
      --cacert service_cert.pem \
      --data-binary @- \
      -H "content-type: application/cose"
    {
        "ballotCount": 0,
        "proposalId": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposerId": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "proposalState": "Open"
    }

Recovery Share Decryption
-------------------------

A member can fetch their encrypted recovery share through :http:GET:`/gov/recovery/encrypted-shares/{memberId}` (see :ref:`governance/accept_recovery:Submitting Recovery Shares`).

The retrieved encrypted recovery share can be decrypted with the encryption key stored in Key Vault:

.. code-block::

    $ az keyvault key decrypt --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --algorithm RSA-OAEP-256 --value <base64_encrypted_share>
    # Outputs base64 decrypted share

The decrypted recovery share can then be submitted to the CCF recovered service (see :ref:`governance/accept_recovery:Submitting Recovery Shares`).