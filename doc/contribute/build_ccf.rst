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

C++ Case Scopes
---------------

Every non-empty ``case`` and ``default`` body must be enclosed in a ``{ ... }`` block, including bodies containing only a single ``return`` or ``break`` statement. Empty stacked labels may share the following block. A nested ``if``, loop, or lambda does not replace the required case block.

After building, run the check from the repository root:

.. code-block:: bash

    $ ./scripts/clang-tidier -p build

``clang-tidier`` uses ``clang-query-18`` or ``clang-query`` from Clang's extra tools, installed by ``scripts/setup-dev.sh``. Set ``CLANG_QUERY`` or pass ``--clang-query`` to select another executable. It checks the first-party C++ translation units in ``compile_commands.json``, including their headers and compile variants, one source file at a time. Vendored ``3rdparty`` files, system headers, and translation units generated in the build directory are excluded. Only code active in that build configuration is checked. Optional source-file arguments restrict local checks to those compilation database entries.

CI runs this check after the Debug build, separately from ``scripts/ci-checks.sh``. Violations, missing tools or files, parse errors, and empty selections fail the check; it does not automatically insert braces.

Update the Documentation
------------------------

It is possible to preview local documentation changes by running

.. code-block:: bash

    $ ./livehtml.sh

or if there are no Doxygen changes

.. code-block:: bash

    $ SKIP_DOXYGEN=ON ./livehtml.sh

HTML builds also build the :ref:`trace viewer <operations/recovery:Trace viewer>`, which needs ``lake``; ``SKIP_TRACE_VIEWER=ON`` skips it.

Rust API documentation
~~~~~~~~~~~~~~~~~~~~~~

HTML builds generate the :doc:`Rust API reference </build_apps/rust_api>` by running ``cargo doc`` on ``src/rust/ccf-app``, without building CCF, and publish it in each version's ``rust/`` directory.
Versions without the SDK are skipped.
Document the SDK in rustdoc comments, and link to its pages from RST with the ``rustdoc`` role:

.. code-block:: rst

    :rustdoc:`Registry <struct.Registry.html>`

Builds fail on rustdoc warnings and broken ``rustdoc`` links.
``SKIP_RUSTDOC=ON`` skips generation and these checks, for local previews only.
Run the SDK doctests with ``cargo test --locked --doc`` in ``src/rust/ccf-app``.
Doctests are linked without CCF, so examples that call into CCF cannot link, even with ``no_run``.
