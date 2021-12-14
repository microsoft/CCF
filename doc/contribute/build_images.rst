CCF Build images
================

CCF build images are produced by running the `docker/app_ci <https://github.com/microsoft/CCF/blob/main/docker/ccf_ci>`_ Docker file,
and pushed to `Docker Hub <https://hub.docker.com/r/ccfciteam/ccf-ci/tags>`_.

Pushing a git tag of the form ``ccf_ci_image/$TAG`` will trigger a `workflow <https://github.com/microsoft/CCF/blob/main/.github/workflows/ci-containers.yml>`_
that builds and pushes a ``ccfciteam/ccf-ci:$TAG`` image.

That image can then be used in CI and CD pipelines.