Building CCF from Source
=========================

Once you have cloned the CCF repository, setup your VM and installed all dependencies, you will be able to successfully build and run the CCF test suite that will deploy a local CCF network.

To build CCF from source on a SGX-enabled machine, run the following:

.. code-block:: bash

    $ cd CCF
    $ mkdir build
    $ cd build
    $ cmake -GNinja ..
    $ ninja

Alternatively, on a non-SGX machine, you can build a `virtual` instance of CCF:

.. code-block:: bash

    $ cd CCF
    $ mkdir build
    $ cd build
    $ cmake -GNinja -DTARGET=virtual ..
    $ ninja

.. note:::

    CCF defaults to building RelWithDebInfo_.

.. _RelWithDebInfo: https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html

Build Switches
--------------

The full list of build switches can be obtained by running:

.. code-block:: bash

    $ cmake -L ..

* **BUILD_TESTS**: Boolean. Build all tests for CCF. Default to ON.
* **BUILD_SMALLBANK**: Boolean. Build SmallBank performance benchmark. Default to OFF.
* **CLIENT_MBEDTLS_PREFIX**: Path. Prefix to mbedtls install to be used by test clients. Default to ``/usr/local``.
* **NO_STRICT_TLS_CIPHERSUITES**: Boolean. Relax the list of accepted TLS ciphersuites. Default to OFF.
* **SAN**: Boolean. Build unit tests with Address and Undefined behaviour sanitizers enabled. Default to OFF.
* **COMPILE_TARGETS**: String. List of target compilation platforms. Defaults to ``sgx;virtual``, which builds both "virtual" enclaves and actual SGX enclaves.
* **VERBOSE_LOGGING**: Boolean. Enable all logging levels. Default to OFF.

Starting up a Test Network
--------------------------

You can quickly spin up a CCF network and start :ref:`issuing commands to the deployed application <users/issue_commands:Issuing Commands>`:

.. code-block:: bash

    $ cd build
    $ ../start_test_network.sh --package ./liblogging.enclave.so.signed
    Setting up Python environment...
    Python environment successfully setup
    [2019-10-29 14:47:41.562] Starting 3 CCF nodes...
    [2019-10-29 14:48:12.138] Started CCF network with the following nodes:
    [2019-10-29 14:48:12.138]   Node [ 0] = 127.177.10.108:37765
    [2019-10-29 14:48:12.138]   Node [ 1] = 127.169.74.37:58343
    [2019-10-29 14:48:12.138]   Node [ 2] = 127.131.108.179:50532
    [2019-10-29 14:48:12.138] You can now issue business transactions to the ./liblogging.enclave.so.signed application.
    [2019-10-29 14:48:12.138] See https://microsoft.github.io/CCF/users/issue_commands.html for more information.
    [2019-10-29 14:48:12.138] Press Ctrl+C to shutdown the network.

Running Tests
-------------

Tests can be started through the ``tests.sh`` wrapper for ctest:

.. code-block:: bash

    $ cd build
    $ ./tests.sh -VV

Although CCF's unit tests can be run through ``ctest`` directly, the end-to-end tests that start a network require some Python infrastructure. `tests.sh <https://github.com/microsoft/CCF/blob/master/tests/tests.sh>`_ will set up a virtual environment with these dependencies and activate it before running ``ctest``. Further runs will re-use that virtual environment.

.. note::
    On a full build of CCF, it is also possible to run tests with virtual enclaves by setting ``TEST_ENCLAVE``:

    .. code-block:: bash

        $ TEST_ENCLAVE=virtual ./tests.sh -VV

    Tests that require enclave attestation will be skipped.


