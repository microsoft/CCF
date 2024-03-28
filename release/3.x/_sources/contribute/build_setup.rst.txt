CCF Development Setup
=====================

Environment Setup
-----------------

First, on your development VM, checkout the CCF repository or :doc:`install the latest CCF release </build_apps/install_bin>`.

Then, to quickly set up the dependencies necessary to build CCF itself and CCF applications, simply run:

.. code-block:: bash

    $ cd <ccf_path>/getting_started/setup_vm
    $ ./run.sh ccf-dev.yml

Once this is complete, you can proceed to :doc:`/build_apps/build_app`.

Build Container
---------------

The quickest way to get started building CCF applications is to use the CCF build container. It contains all the dependencies needed to build and test CCF itself as well as CCF applications.

.. code-block:: bash

    $ export VERSION="3.0.0"
    $ export PLATFORM="sgx" # One of sgx, snp or virtual
    $ docker pull mcr.microsoft.com/ccf/app/dev:$VERSION-$PLATFORM

The container contains the latest release of CCF along with a complete build toolchain, and startup scripts.

If your hardware does support SGX, and has the appropriate driver installed and loaded, then you will only need to expose the device to the container by passing ``--device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v /dev/sgx:/dev/sgx`` when you start it. It can be run on hardware that does not support SGX, in which case you will want to use the virtual binaries, or build in `virtual mode`.

.. note::

    - When running the build container on SGX-enabled hardware, pass the ``--device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v /dev/sgx:/dev/sgx`` options to use SGX in the container.
    - `virtual` mode provides no security guarantee. It is only useful for development and prototyping.

Visual Studio Code Setup
~~~~~~~~~~~~~~~~~~~~~~~~

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample :ccf_repo:`devcontainer.json <.devcontainer/devcontainer.json>` config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-git-repository-or-github-pr-in-an-isolated-container-volume>`_.


.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers

