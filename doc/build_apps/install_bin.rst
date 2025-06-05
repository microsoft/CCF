Install CCF
===========

.. tip:: The `ccf-app-template <https://github.com/microsoft/ccf-app-template>`_ repository can be used to quickly setup the environment necessary to build CCF apps.

Quickstart
----------

CCF builds and runs on Linux. It is primarily developed and tested on `Azure Linux 3.0 <https://github.com/microsoft/azurelinux>`_.
To build a CCF application, installing the `ccf_<platform>_devel` RPM package is sufficient. This package contains the libraries and headers required to build CCF applications.

CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_. They can be installed as follows, for the ``SNP`` and ``Virtual`` platforms:

.. tab:: SNP

    .. code-block:: bash

        # Set CCF_VERSION to most recent LTS release
        $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=6.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_snp_devel_${CCF_VERSION}_x86_64.rpm
        $ sudo tdnf install ./ccf_snp_devel_${CCF_VERSION}_x86_64.rpm

    The following commands can be run to verify that CCF was installed successfully:

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
        $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=6.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_virtual_devel_${CCF_VERSION}_x86_64.rpm
        $ sudo tdnf install ./ccf_virtual_devel_${CCF_VERSION}_x86_64.rpm

    .. warning:: Virtual mode does not provide any security guarantees and should be used for development purposes only.
        
    The following commands can be run to verify that CCF was installed successfully:

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
- Header files and libraries to build CCF applications (under ``include/`` and ``lib/``)
- A limited set of Python utilities to start a basic CCF service for local testing
- Various utility scripts (see :doc:`/build_apps/run_app`)

Uninstall
---------

To remove an installation of CCF, run:

.. tab:: SNP

    .. code-block:: bash

        $ sudo tdnf remove ccf_snp_devel

.. tab:: Virtual

    .. code-block:: bash

        $ sudo tdnf remove ccf_virtual_devel

From Source
-----------

To build and install CCF from source, please see :doc:`/contribute/build_ccf`. The devcontainer is a good way to get started: |Github codespace|

.. |Github codespace| image:: https://img.shields.io/static/v1?label=Open+in&message=GitHub+codespace&logo=github&color=2F363D&logoColor=white&labelColor=2C2C32
   :target: https://codespaces.new/microsoft/CCF?quickstart=1
