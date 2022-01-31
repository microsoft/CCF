Verifying Quote
===============

A client can verify the validity of the SGX quote of the CCF node that it connects to. This can be done using the ``verify_quote.sh`` script installed as part of the CCF install or ccf Python package (see :doc:`/use_apps/python_tutorial`).

.. code-block:: bash

    $ verify_quote.sh https://<ccf-node-address> [--mrenclave <mrenclave_hex>] [CURL_OPTIONS]
    Retrieved 1 accepted code versions from CCF service.
    Node quote successfully retrieved. Verifying quote...
    mrenclave: 3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9
    Quote verification successful.

The script verifies the target CCF node's SGX quote by:

1. Retrieving the node's SGX quote via the :http:GET:`/node/quotes/self` endpoint.
2. Verifying that the cryptographic hash of the node's identity public key (as presented in the node's certificate in the TLS session) matches the quote's report data.
3. Verifying that the quote's measurement (``MRENCLAVE``) matches one of the trusted enclave measurements.

A specific trusted SGX enclave measurement can be specified ``--mrenclave <mrenclave_hex>`` (e.g. using the value returned by the Open Enclave ``oesign dump`` utility) as follows:

.. code-block:: bash

    $ verify_quote.sh https://<ccf-node-address> --mrenclave 3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9 [CURL_OPTIONS]
    Node quote successfully retrieved. Verifying quote...
    mrenclave: 3175971c02d00c1a8f9dd23ca89e64955c5caa94e24f4a3a0579dcfb2e6aebf9
    Quote verification successful.

If no code measurement is specified, the ``verify_quote.sh`` script automatically verifies it against the code versions currently trusted by the CCF service, as returned by the :http:GET:`/node/code` endpoint.

.. note:: The ``verify_quote.sh`` script uses the ``oeverify`` CLI included in the Open Enclave ``hostverify`` package available on the `Open Enclave release page <https://github.com/openenclave/openenclave/releases>`_.

Alternatively, the SGX quotes of all currently trusted nodes can be retrieved via the :http:GET:`/node/quotes` endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quotes --cacert service_cert.pem
    {"quotes": [
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"},
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"}]}
