CCF Build Images
================

CCF build images are produced by running the :ccf_repo:`docker/ccf_ci` Docker file and pushed to the ``ccfmsrc`` Azure Container Registry:

.. code-block:: bash

    $ docker pull ccfmsrc.azurecr.io/ccf-sgx-ci:<tag>

Pushing a git tag of the form ``ccf_ci_image/$TAG`` will trigger a `workflow <https://github.com/microsoft/CCF/blob/main/.github/workflows/ci-containers.yml>`_ that builds and pushes a new ``ccfmsrc.azurecr.io/ccf-sgx-ci:$TAG`` image.

That image can then be used in CI and CD pipelines.