5.x to 6.0 Migration Guide
==========================

This page outlines the major changes introduced in 6.0 and how developers and operators should update their applications and deployments when migrating from 5.x to 6.0.

A full feature list is available in the 6.0 release notes.

To summarise the headline features, we are ending support for SGX platforms, improving the join policy for validating the security of new members, and changing the distribution model for CCF.

Join policy updates
-----------

When a member is started in ``Start`` or ``Recovery`` mode, it populates its local 

When a new network is started with SNP members, the first member prepopulates the join policy with its own environment.
This means that if the network is running on homogenous hardware, the join policy will be automatically populated with the correct values.

This 

Automatically populated join-policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SNP TCB version
~~~~~~~~~~~~~~~



Shipped Artifacts
-----------------

Docker images

Azure Linux and RPM packages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Recovery role
-------------
/