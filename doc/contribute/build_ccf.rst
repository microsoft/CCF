Build CCF from Source
=====================

Once you have setup your VM and installed all dependencies, you will be able to successfully build and run the CCF test suite that will deploy a local CCF network.

First, checkout the CCF repository:

.. code-block:: bash

    $ git clone git@github.com:microsoft/CCF.git

To build CCF from source, run the following:

.. code-block:: bash

    $ cd CCF
    $ mkdir build
    $ cd build
    $ cmake -GNinja .. 
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

Run Tests
---------

Tests can be started through the ``tests.sh`` wrapper for ``ctest``.

.. code-block:: bash

    $ cd build
    $ ./tests.sh

Although CCF's unit tests can be run through ``ctest`` directly, the end-to-end tests that start a network require some Python infrastructure. :ccf_repo:`tests.sh </tests/tests.sh>` will set up a virtual environment with these dependencies and activate it before running ``ctest``. Add ``-VV`` for verbose test output. Further runs will re-use that virtual environment.

Build Older Versions of CCF
---------------------------

Building older versions of CCF may require a different toolchain than the one used to build the current ``main`` branch.
To build a 5.x version of CCF locally without having to install another toolchain that may conflict with the current one, it is possible to use the ``ghcr.io/microsoft/ccf/ci/(default|sgx)`` images.
The version tag of the ``ccf/ci`` image used to build the old version can be found in the :ccf_repo:`.github/workflows/ci.yml` YAML file.

Update the Documentation
------------------------

It is possible to preview local documentation changes by running

.. code-block:: bash

    $ ./livehtml.sh

or if there are no Doxygen changes

.. code-block:: bash

    $ SKIP_DOXYGEN=ON ./livehtml.sh
