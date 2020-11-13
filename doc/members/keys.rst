Members Keys
============

Most of the documentation assumes that the consortium members identity and encryption keys are generated with the ``keygenerator.sh`` script (see :ref:`members/adding_member:Generating Member Keys and Certificates`). However, it is likely that member keys are generated and protected by a dedicated device (e.g. `HSM <https://en.wikipedia.org/wiki/Hardware_security_module>`_). This page explains how...., using `Azure Key Vault <https://en.wikipedia.org/wiki/Hardware_security_module>`_ as the target...

.. note::

    It is assumed that the CCF member has already access to an existing Azure Key Vault. See `here <https://docs.microsoft.com/en-us/azure/key-vault/secrets/quick-create-portal#create-a-vault>`_ for more details on how to create one.

    Using the `Azure CLI <https://docs.microsoft.com/en-us/cli/azure/install-azure-cli>`_, it is possible to check the list of available Key Vault instances:

    .. code-block:: bash

        $ az keyvault list
        # Outputs list of available vaults, including name
        $ export VAULT_NAME="<vault_name>"

Certificate and Key Generation
------------------------------

Members' identity certificates should be generated on the `secp384r1` elliptic curve, using the ``az keyvault certificate create`` command:

.. code-block:: bash

    $ cat cert_policy.json
    {
      "issuerParameters": {
          "certificateTransparency": null,
          "name": "Self"
      },
      "keyProperties": {
          "curve": "P-384",
          "exportable": true,
          "keyType": "EC",
          "reuseKey": true
      },
      "lifetimeActions": [
          {
          "action": {
              "actionType": "AutoRenew"
          },
          "trigger": {
              "daysBeforeExpiry": 90
          }
          }
      ],
      "secretProperties": {
          "contentType": "application/x-pkcs12"
      },
      "x509CertificateProperties": {
          "keyUsage": [
          "digitalSignature"
          ],
          "subject": "CN=Member",
          "validityInMonths": 12
      }
    }

    $ export IDENTITY_CERT_NAME="<identity-cert-name>"
    $ az keyvault certificate create --vault-name $VAULT_NAME -n $IDENTITY_CERT_NAME -p @cert_policy.json
    # Outputs certificate details

    # Corresponding private key is accessible at the same URL (substituting /certificate/ with /key/)
    $ az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Outputs key information, including kid url

Members' encryption keys should be RSA 2048 keys, generated with the ``az keyvault key create`` command:

.. code-block:: bash

    # TODO: Which ops are really required?
    $ export ENCRYPTION_KEY_NAME="<encryption-key-name>"
    $ az keyvault key create --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --kty RSA --ops wrapKey unwrapKey encrypt decrypt
    # Outputs key details, including kid url

The identity certificate and public encryption key can be downloaded to a PEM file and be passed on to members to be registered in a CCF service as a trusted member identity (see :ref:`members/adding_member:Registering a New Member`). Alternatively, if the service has not yet been started, the public member identity can be passed on to operators and registered via the ``cchost --member-info`` option (see :ref:`operators/start_network:Starting the First Node`):

.. code-block:: bash

    $ az keyvault certificate download --file $IDENTITY_CERT_NAME.pem --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Downloads PEM identity certificate

    $ az keyvault key download --file $ENCRYPTION_KEY_NAME.pem --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME
    # Downloads PEM encryption public key

HTTP Request Signature
----------------------

As the Azure CLI (``az keyvault ...``) does not currently support signing/verifying, it is required to use the `corresponding REST API <https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign>`_ instead.

To do so, it is necessary to create a service principal that will be used for authentication:

.. code-block:: bash

    $ export SP_NAME="<sp-name>"
    $ az ad sp create-for-rbac --name $SP_NAME
    # Returns client id (appId), client secret (password)

.. note:: To retrieve the service principal credentials after its creation, the credentials should be refreshed:

    ..code-block:: bash

        $ az ad sp credential reset --name <app_id>
        # Returns client id (appId), updated client secret (password)

Once created, the service principal should be given access to Key Vault in Azure. This can be done through the Azure Portal, under the "Access policies" setting of the vault. The service principal should be given access to the vault with "Sign" key permission. See `here <https://docs.microsoft.com/en-us/azure/key-vault/general/assign-access-policy-portal>`_ for more details.

Then, the following command should be run to retrieve an access token, replacing the values for ``<appid>``, ``<password>`` and ``<tenant>`` with the service principal credentials:

.. code-block:: bash

    export AZ_TOKEN=$(curl -X POST -d "grant_type=client_credentials&client_id=$<appid>&client_secret=<password>&resource=https://vault.azure.net" https://login.microsoftonline.com/<tenant>/oauth2/token | jq -r .access_token)

The member's identity key is now ready to be used for signing:

.. code-block:: bash

    # First, retrieve the kid url for the identity key
    $ export IDENTITY_AKV_KID=$(az keyvault key show --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME --query key.kid --output tsv)

    # Then, sign some hash
    # Note that "value" must be the SHA384 hash of the data to be signed
    $ curl -s -X POST $IDENTITY_AKV_KID/sign?api-version=7.1 --data '{alg: "ES384", "value": "<data_to_sign_sha384>>"}' -H "Authorization: Bearer ${AZ_TOKEN}" -H "Content-Type: application/json" | jq -r .value
    # Outputs signed base64url value

.. note::

    The signatures returned by AKV are returned as a `JWS signature <https://tools.ietf.org/html/rfc7518#section-3.4>`_ and encoded in `base64url <https://tools.ietf.org/html/rfc4648#section-5>`_ format and are not directly compatible with the signatures supported by CCF.

    The ``jws_to_der.py`` Python script can be used to convert a JWS signature generated by AKV to a DER signature compatible with CCF: // TODO: Link to script once checked in

    .. code-block:: bash

        $ python3.8 jws_to_der.py <base64url_signature>
        # Outputs base64 DER signature


Recovery Share Decryption
-------------------------