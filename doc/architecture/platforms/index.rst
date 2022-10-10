Platforms
===================

CCF can run on several platforms, which platform CCF runs on will have impacts on how attestations are verified and therefore what security guarantees you have.

- :doc:`Intel SGX <sgx>`
- :doc:`AMD SEV-SNP (Experimental) <snp>`
- :doc:`Insecure Virtual <virtual>`

Which platform code is run is determined partly by the compile time flag `COMPILE_TARGETS` and partly by runtime detection of the hardware.

CCF networks running a mix of node platforms are not currently supported.
