Platforms
===================

CCF can run on several hardware platforms/trusted execution environments, which will have impact on the security guarantees of the service and on how attestation reports are generated and verified.

.. toctree::
    :maxdepth: 1

    sgx
    snp
    virtual

Which platform code is run is determined partly by the compile time flag ``COMPILE_TARGET`` and partly by runtime detection of the hardware.

.. note:: CCF networks running a mix of node platforms are not currently supported.
