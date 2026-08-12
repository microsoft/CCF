Submitter
=========

Overview
--------

The Submitter component is written in C++ and submits multiple requests with a very high speed to
stress test a system. The source is in :ccf_repo:`tests/perf-system/submitter`. In order to build
the submitter, the required libraries should be installed following the :doc:`/contribute/build_setup`.


Run submitter
--------------

The submitter must be built before use. If the CCF project is already built in your directory,
compile and run it as follows (see :doc:`/contribute/build_ccf` for a first-time build):

.. code-block:: bash

    $ ninja submit

For a full description of all options, run:

.. code-block:: bash

    $ ./submit --help

The submitter requires TLS credentials, addresses, and paths to parquet files produced by
the :doc:`generator`. Some example invocations:

.. code-block:: bash

    # Basic submission against a local node, no pipelining
    $ ./submit \
        --cert member0_cert.pem \
        --key member0_privk.pem \
        --cacert service_cert.pem \
        --server-address 127.0.0.1:8000 \
        --generator-filepath requests.parquet \
        --send-filepath send.parquet \
        --response-filepath responses.parquet

    # Pipelined submission (up to 100 outstanding requests)
    $ ./submit \
        --cert member0_cert.pem \
        --key member0_privk.pem \
        --cacert service_cert.pem \
        --server-address 127.0.0.1:8000 \
        --generator-filepath requests.parquet \
        --send-filepath send.parquet \
        --response-filepath responses.parquet \
        --max-writes-ahead 100

Once the component finishes, the submitted requests and responses are stored in two
``.parquet`` files for subsequent analysis by the :doc:`analysis` component.
