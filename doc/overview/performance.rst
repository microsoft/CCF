Performance
===========

Overview
--------

CCF pairs strong confidentiality guarantees with :ccf_repo:`very high performance </CCF-PAPER-VLDB-2023.pdf>`. CCF can sustain high transaction throughput, while also reaching consensus over commits with low latency.

There are several performance metrics in the CI test suite to ensure this, ranging from micro-benchmarks of critical systems to end-to-end tests measuring peak throughput. These are run against every PR and commit to the main branch. You can also run these locally to test the configuration of your machines, and use them as a basis for creating performance tests of your own CCF application.

Micro-benchmarks
----------------

The micro-benchmark tests can be run from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "bench"

These test performance-critical features of CCF such as certificate verification and KV alterations.


End-to-end performance tests
----------------------------

The end-to-end service performance tests can also be from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "perf" -C "perf"

Each of these tests creates a temporary CCF service on the local machine, then sends a high volume of transactions to measure peak and average throughput. The Python test wrappers print summary statistics including a transaction rate histogram when the test completes.

For a finer grained view of performance the clients in these tests can also dump the precise times each transaction was sent and its response received, for later analysis. The ``samples`` folder contains a ``plot_tx_times`` Python script which produces plots from this data.

Profiling
---------

End-to-end performance tests can be run with the linux utility ``perf`` attached to the nodes to produce profile data. Set the `CCF_PERF` environment variable before running a test to enable this.
