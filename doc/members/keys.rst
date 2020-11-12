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

    $ export ENCRYPTION_KEY_NAME="<encryption-key-name>"
    $ az keyvault key create --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME --kty RSA --ops wrapKey unwrapKey encrypt decrypt
    # Outputs key details, including kid url

The identity certificate and public encryption key can be downloaded to a PEM file and be passed on to members to be registered in a CCF service as a trusted member identity (see :ref:`members/adding_member:Registering a New Member`). Alternatively, if the service has not yet been started, the public member identity can be passed on to operators and registered via the ``cchost --member-info`` option (see :ref:`operators/start_network:Starting the First Node`):

.. code-block:: bash

    $ az keyvault certificate download --file $IDENTITY_CERT_NAME.pem --vault-name $VAULT_NAME --name $IDENTITY_CERT_NAME
    # Downloads PEM identity certificate

    $ az keyvault key download --file $ENCRYPTION_KEY_NAME.pem --vault-name $VAULT_NAME --name $ENCRYPTION_KEY_NAME
    # Downloads PEM encryption public key











HTTP Signature
--------------


Recovery Share Decryption
-------------------------