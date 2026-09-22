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

Rust application documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The HTML build generates the :doc:`Rust API reference </build_apps/rust_api>`
with ``cargo doc --locked --lib --no-deps`` for ``src/rust/ccf-app`` only.
It uses the source version selected by Sphinx and publishes the complete
rustdoc output below that version's ``rust/`` directory. It does not compile
the C++ bridge or a CCF node. Cargo runs from the SDK directory, so rustup
installations use the repository's Rust toolchain file.

Write API contracts and examples as rustdoc comments in the SDK, and use
``literalinclude`` for tutorial snippets from the sample application. The
``rustdoc`` role links to pages and anchors within the current version, for
example:

.. code-block:: rst

    :rustdoc:`Registry <struct.Registry.html>`

HTML builds fail if these targets are missing or rustdoc emits warnings.
Versions predating the SDK skip
generation. ``SKIP_RUSTDOC=ON`` is available for local previews only; it skips
both generation and link validation and must not be used for publishing.

From the repository root, in the documentation Python environment, run:

.. code-block:: bash

    python -m unittest discover -s doc -p 'test_*.py'
    sphinx-build --fail-on-warning -b html doc doc/html
    cd src/rust/ccf-app
    cargo test --locked --doc

The Rust unit-test registration also runs the SDK doctests in CI. Pure Rust
examples can run without CCF; examples using host FFI calls cannot generally
link as standalone doctests, even with ``no_run``. Type-check the sample with
``cargo check --locked --lib`` in ``samples/apps/basic_rust`` and use the
existing ``e2e_basic_rust`` integration test for network behaviour.
