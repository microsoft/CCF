Frequently Asked Questions
===========================

Deployment
----------

“Can CCF run without a Trusted Execution Environment (:term:`TEE`)?”
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CCF can be run on any x86 CPU without a TEE in :doc:`/operations/platforms/virtual` mode. 
However, this mode does not provide any security guarantees (e.g. no memory encryption and no remote attestation) and should not be used for production deployments. 

.. tip:: The :doc:`/operations/platforms/virtual` mode may be useful for development when access to TEE-enabled hardware is limited (e.g. continuous integration pipelines).

“Can CCF run on-prem rather than in Azure?”
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CCF itself can run on prem as well as in Azure. 
However, for the :term:`TEE` security guarantees to be trusted by clients and operators, the deployment environment should have access to the endorsements of the TEE attestation reports.