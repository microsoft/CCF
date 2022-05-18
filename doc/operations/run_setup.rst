Setup CCF Runtime Environment
=============================

Environment Setup
-----------------

First, checkout the CCF repository or :doc:`/build_apps/install_bin`.

Then, to quickly set up the dependencies necessary to start CCF applications, simply run:

.. code-block:: bash

    $ cd <ccf_path>/getting_started/setup_vm
    $ ./run.sh app-run.yml

Runtime Container
-----------------

The ``mcr.microsoft.com/ccf/app/run`` container can be run to setup an environment containing the ``cchost`` binary and the associated dependencies.

The pre-built container can be obtained from the ``mcr.microsoft.com/ccf/app/run`` image on Azure Container Registry:

.. code-block:: bash

   $ docker pull mcr.microsoft.com/ccf/app/run:X.Y.Z-sgx

The container does not contain any particular CCF enclave application, and may be helpful when deploying CCF nodes via docker, k8s, etc. It is up to the operator(s) to mount the appropriate CCF enclave application and start and manage the CCF node.

.. note:: That image is optimised for size above all. If you need an image that comes with peripheral utilities, you probably want the :ref:`Build Container <contribute/build_setup:Build Container>` instead.