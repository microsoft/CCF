Build CCF from Source
=====================

Once you have setup your VM and installed all dependencies, you will be able to successfully build and run the CCF test suite that will deploy a local CCF network.

First, checkout the CCF repository:

.. code-block:: bash

    $ git clone git@github.com:microsoft/CCF.git

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

    CCF defaults to building in the `RelWithDebInfo <https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html>`_ configuration.

Build Switches
--------------

The full list of build switches can be obtained by running:

.. code-block:: bash

    $ cmake -L ..

The most common build switches include:

* **BUILD_TESTS**: Boolean. Build all tests for CCF. Default to ON.
* **BUILD_SMALLBANK**: Boolean. Build SmallBank performance benchmark. Default to OFF.
* **CLIENT_MBEDTLS_PREFIX**: Path. Prefix to mbedtls install to be used by test clients. Default to ``/usr/local``.
* **NO_STRICT_TLS_CIPHERSUITES**: Boolean. Relax the list of accepted TLS ciphersuites. Default to OFF.
* **SAN**: Boolean. Build unit tests with Address and Undefined behaviour sanitizers enabled. Default to OFF.
* **COMPILE_TARGETS**: String. List of target compilation platforms. Defaults to ``sgx;virtual``, which builds both "virtual" enclaves and actual SGX enclaves.
* **VERBOSE_LOGGING**: Boolean. Enable all logging levels. Default to OFF.

Running Tests
-------------

Tests can be started through the ``tests.sh`` wrapper for ``ctest``.

.. code-block:: bash

    $ cd build
    $ ./tests.sh

Although CCF's unit tests can be run through ``ctest`` directly, the end-to-end tests that start a network require some Python infrastructure. `tests.sh <https://github.com/microsoft/CCF/blob/master/tests/tests.sh>`_ will set up a virtual environment with these dependencies and activate it before running ``ctest`` (use ``-VV`` for verbose test output). Further runs will re-use that virtual environment.

.. note::
    On a full build of CCF, it is also possible to run tests with virtual enclaves by setting the ``TEST_ENCLAVE`` environment variable:

    .. code-block:: bash

        $ TEST_ENCLAVE=virtual ./tests.sh [-VV]

    Tests that require enclave attestation will be skipped.


