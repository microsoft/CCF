Setup CCF Runtime Environment
=============================

To run a CCF application, installing the ``ccf`` RPM package is sufficient. This package contains a sample app and expresses runtime dependencies.

CCF releases are available on the `GitHub repository release page <https://github.com/microsoft/CCF/releases>`_. They can be installed as follows:

.. code-block:: bash

    # Set CCF_VERSION to most recent LTS release
    $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
    # Alternatively, set this manually, e.g.:
    # export CCF_VERSION=7.0.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_VERSION}_x86_64.rpm
    $ sudo tdnf install ./ccf_${CCF_VERSION}_x86_64.rpm

The following command can be run to verify that CCF was installed successfully:

.. code-block:: bash

    $ /opt/ccf/bin/js_generic --version
    CCF host: ccf-<version>
    Platform: SNP
