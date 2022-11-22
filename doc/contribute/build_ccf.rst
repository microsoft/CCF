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
    $ cmake -GNinja -DCOMPILE_TARGET=virtual ..
    $ ninja

.. note:::

    CCF defaults to building in the `RelWithDebInfo <https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html>`_ configuration.

.. warning::

    A machine with at least 32Gb of memory is recommended to build CCF with the default compiler.

Build Switches
--------------

The full list of build switches can be obtained by running:

.. code-block:: bash

    $ cmake -L ..

The most common build switches include:

* **BUILD_TESTS**: Boolean. Build all tests for CCF. Default to ON.
* **SAN**: Boolean. Build unit tests with Address and Undefined behaviour sanitizers enabled. Default to OFF.
* **COMPILE_TARGET**: String. Target compilation platform. Defaults to ``sgx``. Supported values are ``sgx``, ``snp``, or ``virtual``.
* **VERBOSE_LOGGING**: Boolean. Enable all logging levels. Default to OFF.

Run Tests
---------

Tests can be started through the ``tests.sh`` wrapper for ``ctest``.

.. code-block:: bash

    $ cd build
    $ ./tests.sh

Although CCF's unit tests can be run through ``ctest`` directly, the end-to-end tests that start a network require some Python infrastructure. :ccf_repo:`tests.sh </tests/tests.sh>` will set up a virtual environment with these dependencies and activate it before running ``ctest``. Add ``-VV`` for verbose test output. Further runs will re-use that virtual environment.

.. note::
    On a full build of CCF, it is also possible to run tests with virtual enclaves by setting the ``TEST_ENCLAVE`` environment variable:

    .. code-block:: bash

        $ TEST_ENCLAVE=virtual ./tests.sh [-VV]

    Tests that require enclave attestation will be skipped.

Build Older Versions of CCF
---------------------------

Building older versions of CCF may require a different toolchain than the one used to build the current ``main`` branch (e.g. 1.x CCF releases are built with `clang-8`). To build an old version of CCF locally without having to install another toolchain that may conflict with the current one, it is recommended to use the ``ccfciteam/ccf-ci`` docker image (now ``ccfmsrc.azurecr.io/ccf/ci``). The version tag of the ``cci-ci`` (now ``ccf/ci``) image used to build the old version can be found in the :ccf_repo:`.azure-pipelines.yml` YAML file (under ``resources:container:image``).

.. code-block:: bash

    $ export CCF_CI_IMAGE_TAG="oe0.17.2-clang-8" # e.g. building CCF 1.0.15
    $ export LOCAL_CCF_CHECKOUT_PATH=/path/to/local/ccf/checkout
    $ cd $LOCAL_CCF_CHECKOUT_PATH
    $ git checkout ccf-1.0.15 # e.g. building CCF 1.0.15
    $ docker run -ti --device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v $LOCAL_CCF_CHECKOUT_PATH:/CCF ccfmsrc.azurecr.io/ccf/ci:$CCF_CI_IMAGE_TAG-sgx bash
    # container started, following lines are in container
     $ cd CCF/
     $ mkdir build_docker && cd build_docker
     $ cmake -GNinja .. && ninja

The built libraries and binaries are then available outside of the container in the ``build_docker`` directory in the local CCF checkout.

Update the Documentation
------------------------

It is possible to preview local documentation changes by running

.. code-block:: bash

    $ ./livehtml.sh

or if there are no Doxygen changes

.. code-block:: bash

    $ SKIP_DOXYGEN=ON ./livehtml.sh