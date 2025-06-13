Setup CCF Runtime Environment
=============================

To run a CCF application, installing the `ccf_<platform>` RPM package is sufficient. This package contains cchost and expresses runtime dependencies.

CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_. They can be installed as follows, for the ``SNP`` and ``Virtual`` platforms:

.. tab:: SNP

    .. code-block:: bash

        # Set CCF_VERSION to most recent LTS release
        $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=6.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_snp_${CCF_VERSION}_x86_64.rpm
        $ sudo tdnf install ./ccf_snp_${CCF_VERSION}_x86_64.rpm

    The following command can be run to verify that CCF was installed successfully:

    .. code-block:: bash

        $ /opt/ccf_snp/bin/cchost --version
        CCF host: ccf-<version>
        Platform: SNP

.. tab:: Virtual

    .. code-block:: bash

        # Set CCF_VERSION to most recent LTS release
        $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
        # Alternatively, set this manually, e.g.:
        # export CCF_VERSION=6.0.0
        $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_virtual_${CCF_VERSION}_x86_64.rpm
        $ sudo tdnf install ./ccf_virtual_${CCF_VERSION}_x86_64.rpm

    .. warning:: Virtual mode does not provide any security guarantees and should be used for development purposes only.
        
    The following command can be run to verify that CCF was installed successfully:

    .. code-block:: bash

        $ /opt/ccf_virtual/bin/cchost --version
        CCF host: ccf-<version>
        Platform: Virtual