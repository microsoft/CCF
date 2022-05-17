CCF Build Images
================

CCF build images are produced by running the :ccf_repo:`docker/ccf_ci` Docker file and pushed to the ``ccfmsrc`` Azure Container Registry. They can be pulled by unauthenticated users:

.. code-block:: bash

    $ docker pull ccfmsrc.azurecr.io/ccf/ci/sgx:<tag>

Pushing a git tag of the form ``ccf_ci_image/$TAG`` will trigger the :ccf_repo:`.github/workflows/ci-containers.yml` workflow that builds and pushes a new ``ccfmsrc.azurecr.io/ccf/ci/sgx:$TAG`` image.

That image can then be used in CI and CD pipelines.

Azure Container Registry Notes
------------------------------

The ``ccfmsrc.azurecr.io`` Azure Container Registry (ACR) has been setup so that all images can be pulled by unauthenticated users (see `documentation <https://docs.microsoft.com/en-us/azure/container-registry/anonymous-pull-access>`_):

.. code-block:: bash
    
    $ az login
    $ az account set --subscription CCF
    $ az acr update --name ccfmsrc --anonymous-pull-enabled

The ``ci-push-token`` has been setup so that only authorised users (in this case the :ccf_repo:`.github/workflows/ci-containers.yml` workflow) can push new ``ccf/ci/sgx`` images:

.. code-block:: bash

    $ az login
    $ az account set --subscription CCF
    # Create d map
    $ az acr scope-map create --name ci-push --registry ccfmsrc --description "Push CCF CI images"
    # Add repository, even before repository is created
    $ az acr scope-map update --name ci-push --registry ccfmsrc --add-repository ccf/ci/sgx content/write content/read
    # Create token, outputs password to add as GitHub ACR_CI_PUSH_TOKEN_PASSWORD secret
    $ az acr token create --name ci-push-token --registry ccfmsrc --scope-map ci-push

.. note:: The ``ccfmsrc`` ACR instance was upgraded to Premium to enable preview features such as `scope maps <https://docs.microsoft.com/en-us/azure/container-registry/container-registry-repository-scoped-permissions#concepts>`_.
