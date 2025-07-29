Reproducible Build
==========================

This section explains how :term:`Users` can reproduce CCF RPM packages using published build manifests.

Reproducible builds enables our published packages to be independently verified. For each official CCF release `published to GitHub <https://github.com/microsoft/CCF/releases>`_, we provide:

- A ``reproduce.json`` manifest containing the container image, snapshot time, and git commit.
- A ``start_container_and_reproduce_rpm.sh`` script needed to reproduce the RPM build.

To reproduce a package:

1. Download the ``reproduce_${PLATFORM}.json`` file for the desired release.
2. Run the ``start_container_and_reproduce_rpm.sh`` script with the manifest as input:

.. code-block:: bash

    # Set CCF_VERSION to most recent LTS release
    $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
    # Alternatively, set this manually, e.g.:
    # export CCF_VERSION=6.0.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/start_container_and_reproduce_rpm.sh
    $ chmod +x ./start_container_and_reproduce_rpm.sh 
    $ ./start_container_and_reproduce_rpm.sh reproduce.json

This builds the RPM in a container and outputs it to ``./reproduced/``. You can then compare it with the official RPM to verify they are identical:

.. code-block:: bash

    # Set CCF_VERSION to most recent LTS release
    $ export CCF_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/microsoft/CCF/releases/latest | sed 's/^.*ccf-//')
    # Alternatively, set this manually, e.g.:
    # export CCF_VERSION=6.0.0
    $ wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_virtual_devel_${CCF_VERSION}_x86_64.rpm
    $ cmp ./ccf_virtual_devel_${CCF_VERSION}_x86_64.rpm ./reproduced/ccf_virtual_devel_${CCF_VERSION}_x86_64.rpm