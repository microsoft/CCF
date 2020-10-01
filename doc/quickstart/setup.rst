Setup CCF Development Environment
=================================

VM Setup
--------

First, on your development VM, checkout the CCF repository or :ref:`install the latest CCF release <quickstart/install:Install CCF>`.

To quickly set up the dependencies necessary to build CCF itself and CCF applications, simply run:

.. code-block:: bash

    $ cd CCF/getting_started/setup_vm
    $ ./run.sh driver.yml # Only on SGX-enabled hardware
    $ ./run.sh ccf-dev.yml

Once this is complete, you can proceed to :ref:`quickstart/build:Building CCF from Source`.

Container
---------

The quickest way to get started building CCF applications is to use the :ref:`developers/build_app:Build Container`.

.. code-block:: bash

    $ docker run -it ccfciteam/ccf-app-ci:latest [--device /dev/sgx:/dev/sgx]

The container contains the latest release of CCF along with a complete build toolchain, and startup scripts.

If your hardware does support SGX, and has the appropriate driver installed and loaded, then you will only need to expose the device to the container by passing ``--device /dev/sgx:/dev/sgx`` when you start it. It can be run on hardware that does not support SGX, in which case you will want to use the virtual binaries, or build in `virtual mode`.

.. note::

    `virtual` mode provides no security guarantee. It is only useful for development and prototyping.

Visual Studio Code Setup
~~~~~~~~~~~~~~~~~~~~~~~~

If you use `Visual Studio Code`_ you can install the `Remote Container`_ extension and use the sample `devcontainer.json`_ config.
`More details on that process <https://code.visualstudio.com/docs/remote/containers#_quick-start-open-a-public-git-repository-in-an-isolated-container-volume>`_.


.. _`Visual Studio Code`: https://code.visualstudio.com/
.. _`Remote Container`: https://code.visualstudio.com/docs/remote/containers
.. _`devcontainer.json`: https://github.com/microsoft/CCF/blob/master/.devcontainer/devcontainer.json

