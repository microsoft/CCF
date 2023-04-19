Setup CCF Runtime Environment
=============================

Environment Setup
-----------------

First, follow the steps described in :doc:`/build_apps/install_bin`.

Then, to quickly set up the dependencies necessary to start CCF applications, simply run:

.. tab:: SGX

    .. code-block:: bash

        $ cd /opt/ccf_sgx/getting_started/setup_vm
        $ ./run.sh app-run.yml --extra-vars "platform=sgx" --extra-vars "clang_version=11"

.. tab:: SNP

    .. code-block:: bash

        $ cd /opt/ccf_snp/getting_started/setup_vm
        $ ./run.sh app-run.yml --extra-vars "platform=snp" --extra-vars "clang_version=15"

.. tab:: Virtual

    .. code-block:: bash

        $ cd /opt/ccf_virtual/getting_started/setup_vm
        $ ./run.sh app-run.yml --extra-vars "platform=virtual" --extra-vars "clang_version=15"


Runtime Containers
------------------

Pre-built runtime container images can be obtained from the `Microsoft Artifact Registry <https://mcr.microsoft.com/en-us/catalog?search=ccf>`_. Note that none of these images are tagged as ``latest`` and so a specific version must always be specified on pull.

The runtime images do not contain any particular CCF application, and may be helpful when deploying CCF nodes via Docker, Kubernetes, etc. It is up to the operator(s) to launch the appropriate CCF application and start and manage the CCF node.

.. note:: The runtime images are optimised for size above all. If you need an image that comes with peripheral utilities, you probably want the :ref:`Build Container <contribute/build_setup:Build Container>` instead.

C++ Apps
~~~~~~~~

The ``mcr.microsoft.com/ccf/app/run`` container can be run to deploy C++ apps. It contains the ``cchost`` binary and the dependencies required to spin up a CCF node.

.. tab:: SGX

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run:$VERSION-sgx

.. tab:: SNP

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run:$VERSION-snp

.. tab:: Virtual

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run:$VERSION-virtual


JavaScript/TypeScript Apps
~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``mcr.microsoft.com/ccf/app/run`` container can be run to deploy JavaScript/TypeScripts apps. It contains the ``cchost`` binary, the ``libjs_generic`` native application to run JavaScript/TypeScript apps, and the dependencies required to spin up a CCF node.

.. tab:: SGX

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run-js:$VERSION-sgx

.. tab:: SNP

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run-js:$VERSION-snp

.. tab:: Virtual

    .. code-block:: bash

        $ export VERSION="4.0.0"
        $ docker pull mcr.microsoft.com/ccf/app/run-js:$VERSION-virtual