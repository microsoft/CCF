CCF Build Images
================

CCF build images are produced by running the :ccf_repo:`docker/ccf_ci` Docker file and pushed to the GitHub Container Repository.
They can be pulled by unauthenticated users:

.. code-block:: bash

    $ docker pull ghcr.io/microsoft/ccf/ci/default:build-*

Pushing a git tag of the form ``build/*`` will trigger the :ccf_repo:`.github/workflows/ci-containers-ghcr.yml` workflow that builds and pushes a new ``ghcr.io/microsoft/ccf/ci/(default|sgx):build-*`` image.

That image can then be used in CI and CD pipelines.
