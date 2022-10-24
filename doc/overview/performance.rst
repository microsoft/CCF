Performance
===========

Overview
--------

CCF pairs strong confidentiality guarantees with :ccf_repo:`very high performance </CCF-TECHNICAL-REPORT.pdf>`. CCF can sustain high transaction throughput, while also reaching consensus over commits with low latency.

There are several performance metrics in the CI test suite to ensure this, ranging from micro-benchmarks of critical systems to end-to-end tests measuring peak throughput. These are run against every PR and commit to the main branch. You can also run these locally to test the configuration of your machines, and use them as a basis for creating performance tests of your own CCF application.

Micro-benchmarks
----------------

The micro-benchmark tests can be run from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "bench"

These test performance-critical features of CCF such as certificate verification and KV-alterations. As an example, here is sample output of ``crypto_bench``:

.. code-block:: bash

    sign secp384r1:
    ===============================================================================
      Name (baseline is *)   |   Dim   |  Total ms |  ns/op  |Baseline| Ops/second
    ===============================================================================
       sign_384_mbed_1byte * |      10 |    13.353 | 1335306 |      - |      748.9
         sign_384_ossl_1byte |      10 |     6.877 |  687683 |  0.515 |     1454.2
            sign_384_mbed_1k |      10 |    13.351 | 1335096 |  1.000 |      749.0
            sign_384_ossl_1k |      10 |     7.045 |  704453 |  0.528 |     1419.5
          sign_384_mbed_100k |      10 |    15.656 | 1565637 |  1.172 |      638.7
          sign_384_ossl_100k |      10 |     8.101 |  810073 |  0.607 |     1234.5
    ===============================================================================
    sign secp256r1:
    ===============================================================================
      Name (baseline is *)   |   Dim   |  Total ms |  ns/op  |Baseline| Ops/second
    ===============================================================================
     sign_256r1_mbed_1byte * |      10 |     8.861 |  886134 |      - |     1128.5
       sign_256r1_ossl_1byte |      10 |     0.183 |   18280 |  0.021 |    54704.3
          sign_256r1_mbed_1k |      10 |     8.916 |  891604 |  1.006 |     1121.6
          sign_256r1_ossl_1k |      10 |     0.199 |   19870 |  0.022 |    50326.9
        sign_256r1_mbed_100k |      10 |    11.952 | 1195225 |  1.349 |      836.7
        sign_256r1_ossl_100k |      10 |     1.786 |  178600 |  0.202 |     5599.1
    ===============================================================================
    verify secp384r1:
    ===============================================================================
      Name (baseline is *)   |   Dim   |  Total ms |  ns/op  |Baseline| Ops/second
    ===============================================================================
     verify_384_mbed_1byte * |      10 |    25.739 | 2573852 |      - |      388.5
       verify_384_ossl_1byte |      10 |     5.179 |  517872 |  0.201 |     1931.0
          verify_384_mbed_1k |      10 |    25.878 | 2587842 |  1.005 |      386.4
          verify_384_ossl_1k |      10 |     5.170 |  516972 |  0.201 |     1934.3
        verify_384_mbed_100k |      10 |    28.007 | 2800703 |  1.088 |      357.1
        verify_384_ossl_100k |      10 |     6.208 |  620803 |  0.241 |     1610.8
    ===============================================================================
    verify secp256r1:
    ===============================================================================
      Name (baseline is *)   |   Dim   |  Total ms |  ns/op  |Baseline| Ops/second
    ===============================================================================
   verify_256r1_mbed_1byte * |      10 |    17.673 | 1767258 |      - |      565.8
     verify_256r1_ossl_1byte |      10 |     0.482 |   48160 |  0.027 |    20764.0
        verify_256r1_mbed_1k |      10 |    17.568 | 1756758 |  0.994 |      569.2
        verify_256r1_ossl_1k |      10 |     0.498 |   49820 |  0.028 |    20072.1
      verify_256r1_mbed_100k |      10 |    20.771 | 2077120 |  1.175 |      481.4
      verify_256r1_ossl_100k |      10 |     2.085 |  208471 |  0.118 |     4796.8
    ===============================================================================
    hash:
    ===============================================================================
      Name (baseline is *)   |   Dim   |  Total ms |  ns/op  |Baseline| Ops/second
    ===============================================================================
        sha_384_mbed_1byte * |      10 |     0.003 |     340 |      - |  2941176.5
          sha_256_mbed_1byte |      10 |     0.003 |     290 |  0.853 |  3448275.9
          sha_512_mbed_1byte |      10 |     0.004 |     350 |  1.029 |  2857142.9
          sha_384_ossl_1byte |      10 |     0.004 |     360 |  1.059 |  2777777.8
          sha_256_ossl_1byte |      10 |     0.003 |     290 |  0.853 |  3448275.9
          sha_512_ossl_1byte |      10 |     0.004 |     390 |  1.147 |  2564102.6
             sha_384_mbed_1k |      10 |     0.024 |    2400 |  7.059 |   416649.3
             sha_256_mbed_1k |      10 |     0.035 |    3460 | 10.176 |   289017.3
             sha_512_mbed_1k |      10 |     0.024 |    2440 |  7.176 |   409836.1
             sha_384_ossl_1k |      10 |     0.015 |    1460 |  4.294 |   684931.5
             sha_256_ossl_1k |      10 |     0.018 |    1850 |  5.441 |   540540.5
             sha_512_ossl_1k |      10 |     0.015 |    1530 |  4.500 |   653594.8
           sha_384_mbed_100k |      10 |     2.039 |  203891 |599.679 |     4904.6
           sha_256_mbed_100k |      10 |     3.053 |  305291 |897.916 |     3275.6
           sha_512_mbed_100k |      10 |     2.039 |  203901 |599.709 |     4904.3
           sha_384_ossl_100k |      10 |     1.061 |  106090 |312.031 |     9425.9
           sha_256_ossl_100k |      10 |     1.592 |  159150 |468.091 |     6283.3
           sha_512_ossl_100k |      10 |     1.064 |  106380 |312.884 |     9400.2
    ===============================================================================


End-to-end performance tests
----------------------------

The end-to-end service performance tests can also be from the CCF build directory:

.. code-block:: bash

    ./tests.sh -VV -L "perf"

Each of these tests creates a temporary CCF service on the local machine, then sends a high volume of transactions to measure peak and average throughput. The python test wrappers will print summary statistics including a transaction rate histogram when the test completes. These statistics can be retrieved from any CCF service via the ``getMetrics`` RPC.

For a finer grained view of performance the clients in these tests can also dump the precise times each transaction was sent and its response received, for later analysis. The ``samples`` folder contains a ``plot_tx_times`` Python script which produces plots from this data.