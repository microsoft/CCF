CCF Build Images
================

CCF build images are produced by running the :ccf_repo:`docker/ccf_ci` Docker file and pushed to the ``ccfmsrc`` Azure Container Registry. They can be pulled by unauthenticated users:

.. code-block:: bash

    $ docker pull ccfmsrc.azurecr.io/ccf/ci/sgx:<tag>

Pushing a git tag of the form ``ccf_ci_image/$TAG`` will trigger the :ccf_repo:`.github/workflows/ci-containers.yml` workflow that builds and pushes a new ``ccfmsrc.azurecr.io/ccf/ci/sgx:$TAG`` image.

That image can then be used in CI and CD pipelines.
