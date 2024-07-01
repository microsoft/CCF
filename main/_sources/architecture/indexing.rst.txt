Indexing
========

CCF supports the creation of endpoints which process historical state.
Historical transactions are asynchronously fetched from the ledger, verified and decrypted, and presented to the application endpoint for processing.
These queries can also operate on a range of historical transactions, and build an aggregated result.
The framework handles all details of fetching and validating these entries, to present a simple API to the application programmer.

Fetching each transaction on-demand is too slow for some use cases, especially for historical queries which may be called regularly.
To improve the performance of this kind of query, the framework provides a generic indexing system.
Applications can define and install a :cpp:type:`ccf::indexing::Strategy` for processing historical queries.
Each strategy will be given the raw contents of transactions shortly after they are committed, and can build its own index ahead of a user-query.
This index is built once but may be queried many times, preventing duplicate fetches and processing for duplicate queries.

For instance, if we want to answer a query like "tell me the TxID of every transaction which wrote to this table", we could write a strategy which stores a large list of those TxIDs as it sees them.

This indexing system and all the strategies it manages exist entirely within the enclave, so have the same trust guarantees as any other in-enclave code.
This means users can trust that these queries are accurate and complete, and may deal with private data, in a way which is not possible with out-of-enclave ledger processing.

LFS
---

To prevent these indexes from growing indefinitely and exhausting the enclave memory budget, there is an additional system for offloading chunks of memory to the host, to be stored on disk.
In the CCF codebase, this is referred to as the LFS (Large File Storage) system.
In the example above, the list of TxIDs may grow linearly with the ledger.
Rather than holding the entire index in-memory the strategy would offload chunks of it to the host - keeping a small cache in-memory and rapidly available, with the full data set available asynchronously by requesting it from the host.

To maintain the trust guarantees of this offloaded data, it must be carefully handled:

* Integrity protected, to prevent the host tampering with the index.
* Encrypted, to prevent the host reading indexes of confidential state.
* Reproducible, to recover a complete index if the host tampers with or hides the data.
* *Additionally obfuscated/padded? The existence of index blobs tells the host some information about the KV state. How much information leakage is acceptable here, and how much can we avoid by padding?*

In the current design these indexes are entirely node-local and never shared, so a node only needs to be able to decipher its own index files.
For simplicity, we aim to provide the same protections on all data rather than distinguishing public and private data at this stage.
While we consider this scheme further, only data from public tables will be indexed in this way, to avoid leakage of confidential data.

The intended high-level flow is as follows:

* A strategy produces a blob of data for the LFS system inside the enclave to store: ``store(name, data)``

* The LFS system generates an obfuscated name ``name'`` and encrypts the data ``data'``

* The LFS system passes ``name'`` and ``data'`` to the host

* Later, the strategy returns to the LFS system and requests that blob: ``fetch(name)``

* The LFS system generates ``name'``, and requests this from the host

* The host responds with some data ``D``

* The in-enclave LFS system verifies that ``D`` == ``data'``, decrypts to ``data``, and provides ``data`` to the caller

Clearly ``data`` must be encrypted and integrity protected to prevent trivial information reveal/tampering.
Additionally, both ``name`` and the size of ``data'`` may reveal some information about the contents.
We want the name obfuscation to limit the former, and will explore padding options for the latter.

The current details, and open questions, are:

* We expect ``name`` and ``data`` to always be a matching pair, once the LFS has seen it. So we are not appending incrementally different values of ``data`` each time, and even if we re-index in future we will produce identical values.

* A node generates a fresh AES-GCM key |K_LFS| on startup, which never leaves the enclave. This will be used to encrypt and decrypt all of its LFS files, and lives as long as the node.

   * Should this be derived from the node key?
   * *This should be rotated rather than used indefinitely! But does the derived key need to be determined from ``name``, or can it be specified by ``D``?*
   * Should this just be a HKDF derived key per-file (aka per-``name``)?

* To fetch, we need to produce ``name'`` from ``name``. So if we want to derive a salt to hash with, it must be derived from the secret key.

* ``data'`` is the AES-GCM encryption of ``data``, using |K_LFS| and a randomly selected IV.

   * The host could convince a node to re-index, potentially producing ``data_a'``, ``data_b'``, ``data_c'``, with different IVs but from the same plaintext ``data``. Is this a risk?

* How should we confirm that we've got the correct ``data_a``, and not some other (created by us) ``data_b``? Embed some fingerprint bytes in the IV, or prefix the encrypted message (currently doing the latter)?

.. note::

    The LFS system is currently only used by indexing strategies, but may be used for additional tasks in future to implement a framework-level memory cache.

.. |K_LFS| replace:: K :sub:`LFS`