Using Member Keys Stored in HSM
===============================

This page explains how members' identity certificates and encryption keys stored in an `HSM <https://en.wikipedia.org/wiki/Hardware_security_module>`_ can be used with CCF. The following guide describes the usage of `Azure Key Vault <https://azure.microsoft.com/en-gb/services/key-vault>`_

.. note::

    It is assumed that CCF members already have access to an existing Azure Key Vault. See `these instructions <https://docs.microsoft.com/en-us/azure/key-vault/general/quick-create-portal#create-a-vault>`_ for more details on how to create one. Using the `Azure CLI <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli>`_, it is possible to check the list of available Key Vault instances:

    .. code-block:: bash

        $ az keyvault list
        # Outputs list of available vaults, including name
        $ export VAULT_NAME="<vault_name>"

Certificate and Key Generation
------------------------------

Members' identity certificates should be generated on the `secp384r1` elliptic curve, using the `az keyvault certificate create <https://docs.microsoft.com/en-us/cli/azure/keyvault/certificate?view=azure-cli-latest#az-keyvault-certificate-create>`_ command, with the following ``identity_cert_policy_example.json`` policy:

.. include:: akv_identity_cert_policy.json
    :literal:

.. code-block:: bash

    $ export IDENTITY_CERT_NAME="<identity-cert-name>"
    $ az keyvault certificate create --vault-name $VAULT_NAME -n $IDENTITY_CERT_NAME -p @identity_cert_policy_example.json
    # Outputs certificate details

    # Corresponding private key is accessible at the same URL (substituting /certificate/ with /key/)
    $ az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Outputs key information, including kid url

Members' encryption keys should be RSA 2048 keys, generated with the `az keyvault key create <https://docs.microsoft.com/en-us/cli/azure/keyvault/key?view=azure-cli-latest#az-keyvault-key-create>`_ command:

.. code-block:: bash

    $ export ENCRYPTION_KEY_NAME="<encryption-key-name>"
    $ az keyvault key create --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --kty RSA --ops decrypt
    # Outputs key details, including kid url

The identity certificate and public encryption key can be downloaded to a PEM file and be passed on to members to be registered in a CCF service as a trusted member identity (see :ref:`governance/adding_member:Registering a New Member`). Alternatively, if the service has not yet been started, the public member identity can be passed on to operators and registered via the ``command.start.members`` configuration entry (see :ref:`operations/start_network:Starting the First Node`):

.. code-block:: bash

    $ az keyvault certificate download --file $IDENTITY_CERT_NAME.pem --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Downloads PEM identity certificate

    $ az keyvault key download --file $ENCRYPTION_KEY_NAME.pem --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME
    # Downloads PEM encryption public key

Signing Governance Requests
---------------------------

As the Azure CLI (``az keyvault ...``) does not currently support signing/verifying, it is required to use the `corresponding REST API <https://docs.microsoft.com/en-us/rest/api/keyvault/keys/sign/sign>`_ instead. To do so, it is necessary to create a service principal that will be used for authentication:

.. code-block:: bash

    $ export SP_NAME="<sp-name>"
    $ az ad sp create-for-rbac --name $SP_NAME
    # Returns client id (appId), client secret (password)

.. note:: To retrieve the service principal credentials after its creation, the credentials should be refreshed:

    .. code-block:: bash

        $ az ad sp credential reset --name <app_id>
        # Returns client id (appId), updated client secret (password)

Once created, the service principal should be given access to Key Vault in Azure. This can be done through the Azure Portal, under the "Access policies" setting of the vault. The service principal should be given access to the vault with "Sign" key permission. See `here <https://docs.microsoft.com/en-us/azure/key-vault/general/assign-access-policy-portal>`_ for more details.

Then, the following command should be run to retrieve an access token, replacing the values for ``<appid>``, ``<password>`` and ``<tenant>`` with the service principal credentials:

.. code-block:: bash

    export AZ_TOKEN=$(curl -X POST -d "grant_type=client_credentials&client_id=<appid>&client_secret=<password>&resource=https://vault.azure.net" https://login.microsoftonline.com/<tenant>/oauth2/token | jq -r .access_token)

The member's identity key is now ready to be used for signing governance requests.

COSE Signing
~~~~~~~~~~~~

As an alternative to the ``ccf_cose_sign1`` script when signing offline, CCF provides the ``ccf_cose_sign1_prepare`` and ``ccf_cose_sign1_finish`` scripts.

``ccf_cose_sign1_prepare`` takes the same arguments as ``ccf_cose_sign1``, minus the signing key, to produce a payload that can be sent to AKV:

.. code-block:: bash

    # Retrieve the digest to be signed
    $ ccf_cose_sign1_prepare --ccf-gov-msg-type proposal --content proposal.json --signing-cert $IDENTITY_CERT_NAME.pem > tbs
    $ cat tbs
    {"alg": "ES384", "value": "dUDKb1pqdi22R3gojLDiK4chPG5it3IaHxNbsuO3APIhlvo7pa16BX7miGPzx7Sy"} # To be signed by AKV

    # Retrieve the kid url for the identity key
    $ export IDENTITY_AKV_KID=$(az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME --query key.kid --output tsv)

    # Send the digest to the key management service for signing 
    $ curl -s -X POST $IDENTITY_AKV_KID/sign?api-version=7.1 --data @tbs -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" > signature

Finally, COSE Sign1 payload can be assembled with ``ccf_cose_sign1_finish``:

.. code-block:: bash

    $ ccf_cose_sign1_finish --ccf-gov-msg-type proposal --content proposal.json --signing-cert $IDENTITY_CERT_NAME.pem --signature signature > cose_sign1

Like ``ccf_cose_sign1``, the output can be sent directly to the service via curl:

.. code-block:: bash

    $ ccf_cose_sign1_finish --ccf-gov-msg-type proposal --content proposal.json --signing-cert $IDENTITY_CERT_NAME.pem --signature |\
      curl https://<ccf-node-address>/gov/proposals --cacert service_cert.pem --data-binary @- -H "content-type: application/cose"
    {
        "ballot_count": 0,
        "proposal_id": "1b7cae1585077104e99e1860ad740efe28ebd498dbf9988e0e7b299e720c5377",
        "proposer_id": "d5d7d5fed6f839028456641ad5c3df18ce963bd329bd8a21df16ccdbdbba1eb1",
        "state": "Open"
    }

HTTP Signing
~~~~~~~~~~~~

The ``scurl.sh`` script can be used with the ``--print-digest-to-sign`` option to print the SHA384 to be signed as well as the required headers for HTTP signatures (following the `draft-cavage-http-signatures-12 <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_ scheme):

.. code-block:: bash

    # First, retrieve the hash to be signed
    $ scurl.sh https://<ccf-node-address>/gov/<endpoint> -X [GET|POST] --signing-cert $IDENTITY_CERT_NAME.pem --print-digest-to-sign
    Hash to sign: <hash_to_sign> # To be signed by AKV
    Request headers:
    -H 'Digest: SHA-256=...'
    -H 'Authorization: Signature keyId="...",algorithm="hs2019",headers="(request-target) digest content-length",signature="<insert_base64_signature_here>"' # Replace signature with AKV signature here
    -H 'content-length: 0'

    # Then, retrieve the kid url for the identity key
    $ export IDENTITY_AKV_KID=$(az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME --query key.kid --output tsv)

    # Then, sign the request hash to be signed (as output by scurl.sh --print-digest-to-sign)
    $ export base64url_signature=$(curl -s -X POST $IDENTITY_AKV_KID/sign?api-version=7.1 --data '{alg: "ES384", "value": "<hash_to_sign>"}' -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" | jq -r .value)

.. note:: The signatures returned by AKV are returned as a `JWS signature <https://tools.ietf.org/html/rfc7518#section-3.4>`_ and encoded in `base64url <https://tools.ietf.org/html/rfc4648#section-5>`_ format and are not directly compatible with the signatures supported by CCF.

The :ccf_repo:`jws_to_der.py </doc/governance/jws_to_der.py>` Python script can be used to convert a JWS signature generated by AKV to a DER signature compatible with CCF:

.. code-block:: bash

    $ pip install pyasn1
    $ export ccf_signature=$(python3.8 jws_to_der.py $base64url_signature)

Finally, the signed HTTP request can be issued, using the request headers printed by ``scurl.sh --print-digest-to-sign``:

.. code-block:: bash

    $ curl https://<ccf-node-address>/gov/<endpoint> -X [GET|POST] --cert $IDENTITY_CERT_NAME.pem \
    -H 'Digest: SHA-256=...' \
    -H 'Authorization: Signature keyId="...",algorithm="hs2019",headers="(request-target) digest content-length",signature="$ccf_signature"' \
    -H 'content-length: <content-length>'

Recovery Share Decryption
-------------------------

To retrieve their encrypted recovery share, a member should issue a COSE Sign1 or signed HTTP request against the ``/gov/recovery_share`` endpoint (see :ref:`governance/accept_recovery:Submitting Recovery Shares`). Signing the request will allow the member to authenticate themself to CCF (see :ref:`governance/hsm_keys:Signing Governance Requests`).

The retrieved encrypted recovery share can be decrypted with the encryption key stored in Key Vault:

.. code-block::

    $ az keyvault key decrypt --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --algorithm RSA-OAEP-256 --value <base64_encrypted_share>
    # Outputs base64 decrypted share

The decrypted recovery share can then be submitted to the CCF recovered service (see :ref:`governance/accept_recovery:Submitting Recovery Shares`).