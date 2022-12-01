Read-Write Permissions On KV Maps
=================================

To allow governance audit we ensure that all governance actions can be viewed and understood from the ledger, which means they must operate over public tables. To support this CCF distinguishes governance tables from application tables, and restricts which tables can be read from and written to in different execution contexts.

Table Namespaces
----------------

There are 3 categories of table defined:

- Governance tables. These begin with a ``public:ccf.gov`` prefix, indicating that they are public (their contents are not encrypted in the ledger), and in the ``ccf.gov`` namespace. These should only be modified by constitution-controlled governance actions.
- Internal tables. These begin with a ``ccf.internal`` or ``public:ccf.internal`` prefix, indicating that they are in the ``ccf.internal`` namespace, and may be public or private. These can be considered a lower-level subset of governance tables, though some are also modified by node-triggered operations such as signatures, rather than governance actions.
- Application tables. This includes any other table name. These are the tables that application endpoints should modify.

.. warning::

    Table names are case sensitive. So ``public:CCF.gov.users`` (upper-case "CCF") is an `application` table, not a governance table.

.. note::

    All other tables in the ``ccf`` namespace are reserved for future use, so attempting to access any table beginning ``ccf.`` which is not in the governance or internal namespace will result in an error.

Execution Contexts
------------------

There are several possible contexts in which developer-specified code may execute within a CCF node:

- Pre-approval governance context. These pieces of code may read from the KV to make decisions, but may not make any modifications to it, as they represent pending, unapproved operations. Specifically, this context applies:

    - when evaluating member ballots
    - when evaluating the constitution's ``validate`` function
    - when evaluating the constitution's ``resolve`` function

- Post-approval governance context. These pieces of code run only for accepted proposals, after a quorum of members have voted to approve it, so are permitted to make modifications to the KV. Specifically, this context applies:

    - when evaluating the constitution's ``apply`` function

- Application context. These pieces of code execute endpoint handlers to implement the application logic, are invoked to handle incoming user requests, and may read and write from application tables.

.. note::

    Since the constitution (and JS application) are written in JavaScript, there is also technically a global module evaluation context when the code is first ingested. It is expected that this only defines and exports the necessary functions. It has no access to the KV, and will result in errors if it attempts to access any KV table.

Restricted Permissions
----------------------

CCF ensures that governance audit is possible offline from a ledger, by considering only a subset of transactions. These governance transactions operate purely over governance tables, so that governance audit does not need to consider application tables, and purely over public tables so that all decisions can be reconstructed from the ledger. Combining the definitions above, we impose several restrictions on KV access in different contexts:

- Governance code must never read from private tables. Doing so might make decisions which could not be reproduced from the ledger.
- Governance code running pre-approval must only have read access to tables, and never write.
- Governance code should not write to application tables, which could be modified further outside of governance.
- Application code must not modify governance tables, as it could do so without constitution approval.

.. note:: 

    An important exemption here is that application code may still `read` from governance tables. This allows authentication, authorization, and metadata to be configured and controlled by governance, but affect the execution of application endpoints.

The possible combinations are elaborated in the table below:

.. table:: KV Permissions in different execution contexts
    :widths: auto

    +--------------------------+-----------------------------------------------------------------------------+
    |                          | Table Category                                                              |
    |                          +-------------------------+-------------------------+-------------------------+
    |                          | Internal                | Governance              | Application             |
    +--------------------------+------------+------------+------------+------------+------------+------------+
    | Execution context        | Public     | Private    | Public     | Private    | Public     | Private    |
    +==========================+============+============+============+============+============+============+
    | Pre-approval governance  | Read-only  | None       | Read-only  | None       | Read-only  | None       |
    +--------------------------+------------+------------+------------+------------+------------+------------+
    | Post-approval governance | Read-only  | None       | Writeable  | None       | Read-only  | None       |
    +--------------------------+------------+------------+------------+------------+------------+------------+
    | Application              | Read-only  | Read-only  | Read-only  | Read-only  | Writeable  | Writeable  |
    +--------------------------+------------+------------+------------+------------+------------+------------+

Any violation of these restrictions (eg - calling ``set`` on a read-only table, or ``has`` on an unreadable table) results in an exception being thrown.