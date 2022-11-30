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

- Read-only governance context. These pieces of code may read from the KV to make decisions, but may not make any modifications to it, as they represent pending, unapproved operations. Specifically, this context applies:

    - when evaluating member ballots
    - when evaluating the constitution's ``validate`` function
    - when evaluating the constitution's ``resolve`` function

- Read-write governance context. These pieces of code run only for accepted proposals, after a quorum of members have voted to approve it, so are permitted to make modifications to the KV. Specifically, this context applies:

    - when evaluating the constitution's ``apply`` function

- Application context. These pieces of code execute endpoint handlers to implement the application logic, and may read and write from application tables.

Restricted Permissions
----------------------

Combining the definitions above, we impose several restrictions on KV access in different contexts:

- Governance code must never read from private tables. Doing so would produce