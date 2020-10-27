Verifying Quote
===============

A client can verify the SGX quote of the CCF node that it connects to.

First, the client should connect to the node to verify, specifying the ``/node/quote`` endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quote --cacert networkcert.pem
    {"quotes": [{"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"}]}

The raw quote should be decoded and output to file for verification via the Open Enclave ``oeverify`` command-line utility:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quote --cacert networkcert.pem | jq .raw | xxd -r -p > ccf_node_quote.bin

    $ /opt/openenclave/bin/oeverify -r ccf_node_quote.bin -f LEGACY_REPORT_REMOTE
    Verifying evidence ccf_node_quote.bin...
    Claims:
    Enclave unique_id: <ccf_node_mrenclave>
    Enclave signer_id: <ccf_node_mrsigner>
    Enclave product_id: <ccf_node_product_id>
    Enclave sgx_report_data: <ccf_node_report_data>
    Evidence verification succeeded (0)

.. note:: The ``oeverify`` CLI is included in the Open Enclave ``hostverify`` package available on the `Open Enclave release page <https://github.com/openenclave/openenclave/releases>`_.

The SGX quotes of all currently trusted nodes can also be retrieved via the ``/node/quotes`` endpoint:

.. code-block:: bash

    $ curl https://<ccf-node-address>/node/quotes --cacert networkcert.pem
    {"quotes": [
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"},
    {"mrenclave":"<measurement_hash>, "node_id":<node_id>, "raw":"<hex_encoded_raw_quote>"}]}
