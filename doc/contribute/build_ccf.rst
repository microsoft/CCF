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

.. note::

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
* **CCF_STACKTRACE_BACKEND**: ``AUTO`` (default), ``STD``, or ``LIBBACKTRACE``. Selects the task exception stacktrace implementation.

Task Stacktraces
~~~~~~~~~~~~~~~~

``AUTO`` prefers C++23 ``std::stacktrace`` when the active compiler and standard library can compile and link its required operations, trying the default libraries, ``stdc++exp``, then ``stdc++_libbacktrace``. Otherwise it requires standalone libbacktrace headers and a library. ``STD`` and ``LIBBACKTRACE`` fail configuration if the requested backend is unavailable.

Configuration reports the selected backend and support library. The installed ``ccf_tasks`` target propagates its support-library and dynamic-loader dependencies by link name. Azure Linux 4's standard support archive requires the matching ``libstdc++-devel`` package; Azure Linux 3's fallback requires ``libbacktrace-static``.

Run Tests
---------

Tests can be started through the ``tests.sh`` wrapper for ``ctest``.

.. code-block:: bash

    $ cd build
    $ ./tests.sh

Although CCF's unit tests can be run through ``ctest`` directly, the end-to-end tests that start a network require some Python infrastructure. :ccf_repo:`tests.sh </tests/tests.sh>` will set up a virtual environment with these dependencies and activate it before running ``ctest``. Add ``-VV`` for verbose test output. Further runs will re-use that virtual environment.

Update the Documentation
------------------------

It is possible to preview local documentation changes by running

.. code-block:: bash

    $ ./livehtml.sh

or if there are no Doxygen changes

.. code-block:: bash

    $ SKIP_DOXYGEN=ON ./livehtml.sh
