Install CCF
===========

.. tip:: The `ccf-app-template <https://github.com/microsoft/ccf-app-template>`_ repository can be used to quickly setup the environment necessary to build CCF apps.

Quickstart
----------

CCF builds and runs on Linux. It is primarily developed and tested on Ubuntu 20.04.
The dependencies required to build and run CCF apps can be conveniently installed using the ``ansible`` playbooks in the CCF repository or `Install`_, depending on the target TEE platform:

.. tab:: SNP

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm/
        $ ./run.sh app-dev.yml --extra-vars "platform=snp"

.. tab:: Virtual

    .. warning:: The `virtual` version of CCF can also be run on hardware that does not support SEV-SNP. Virtual mode does not provide any security guarantees and should be used for development purposes only.

    .. code-block:: bash

        $ cd <ccf_path>/getting_started/setup_vm/
        $ ./run.sh app-dev.yml --extra-vars "platform=virtual"
        
This will install the latest release of CCF, but a specific release can also be specified with ``--extra-vars "ccf_ver=X.Y.Z"`` if desired.

.. _Install:

Installation from .deb
----------------------

Alternatively, CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_.

The CCF Debian package (``ccf_<platform>_<version>_amd64.deb``) contains the libraries and utilities to start a CCF service and build CCF applications. CCF can be installed as follows, for the ``SNP`` and ``Virtual`` platforms:

.. tab:: SNP

    .. code-block:: bash

        # Set CCF_VERSION to most recent LTS release
        $ export CCF_VERSION=$(curl -ILs -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=4.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_snp_${CCF_VERSION}_amd64.deb
        $ sudo apt install ./ccf_snp_${CCF_VERSION}_amd64.deb

        
    Assuming that CCF was installed under ``/opt``, the following commands can be run to verify that CCF was installed successfully:

    .. code-block:: bash

        $ /opt/ccf_snp/bin/cchost --version
        CCF host: ccf-<version>
        Platform: SNP

        $ /opt/ccf_snp/bin/sandbox.sh
        No package/app specified. Defaulting to installed JS logging app
        Setting up Python environment...
        Python environment successfully setup
        [16:10:16.552] Starting 1 CCF node...
        [16:10:23.349] Started CCF network with the following nodes:
        [16:10:23.350]   Node [0] = https://127.0.0.1:8000
        ...

.. tab:: Virtual

    .. code-block:: bash

        # Set CCF_VERSION to most recent LTS release
        $ export CCF_VERSION=$(curl -ILs -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=4.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_virtual_${CCF_VERSION}_amd64.deb
        $ sudo apt install ./ccf_virtual_${CCF_VERSION}_amd64.deb

    .. warning:: Virtual mode does not provide any security guarantees and should be used for development purposes only.
        
    Assuming that CCF was installed under ``/opt``, the following commands can be run to verify that CCF was installed successfully:

    .. code-block:: bash

        $ /opt/ccf_virtual/bin/cchost --version
        CCF host: ccf-<version>
        Platform: Virtual

        $ /opt/ccf_virtual/bin/sandbox.sh
        No package/app specified. Defaulting to installed JS logging app
        Setting up Python environment...
        Python environment successfully setup
        [16:10:16.552] Starting 1 CCF node...
        [16:10:16.552] Virtual mode enabled
        [16:10:23.349] Started CCF network with the following nodes:
        [16:10:23.350]   Node [0] = https://127.0.0.1:8000
        ...

------------

The CCF install notably contains:

- The ``cchost`` binary required to spin up a CCF application
- The ``cmake`` files required to build CCF applications
- The ``ansible`` playbooks required for :doc:`/contribute/build_setup` (under ``getting_started/``)
- Header files and libraries to build CCF applications (under ``include/`` and ``lib/``)
- A limited set of Python utilities to start a basic CCF service for local testing
- Various utility scripts (see :doc:`/build_apps/run_app`)

Uninstall
---------

To remove an installation of CCF, run:

.. tab:: SNP

    .. code-block:: bash

        $ sudo apt remove ccf_snp

.. tab:: Virtual

    .. code-block:: bash

        $ sudo apt remove ccf_virtual

From Source
-----------

To build and install CCF from source, please see :doc:`/contribute/build_ccf`.