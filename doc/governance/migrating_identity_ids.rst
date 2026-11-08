Migrating Users and Members to did:key
======================================

This guide describes how to move an existing user or member from its legacy SHA-256 ID to a ``did:key`` ID.
The DID is derived from the identity public key, so using a certificate with the same key preserves the DID.
Changing an enrolled ID is not an in-place operation: CCF does not create an alias, change existing ledger entries, or copy identity data between IDs.

Before migrating, upgrade every node in the service to a version that supports ``did:key`` IDs.
See :ref:`architecture/cryptography:Identity IDs` for compatibility and identity semantics.

Derive the new ID from the certificate that will be enrolled:

.. code-block:: bash

    $ python3 -m ccf.identity --cert identity_cert.pem --id-format did:key
    did:key:z...

The same public key always produces the same DID, regardless of certificate renewal.
The ID format is scoped to each role: the same public key may be enrolled as a member and a user, but cannot be enrolled in both formats at the same time within either role.
Therefore, remove the legacy enrollment and wait for that proposal to be accepted before proposing the ``did:key`` enrollment.
This creates an access gap between the two accepted proposals; schedule the change accordingly.

Migrating a user
----------------

Before removing the user, record its current user data and the certificate associated with its legacy ID.
The ``remove_user`` action deletes the user's certificate and user data, so include the saved user data when enrolling the DID identity.

First, submit and get approval for a proposal that removes the legacy identity:

.. code-block:: json

    {
      "actions": [
        {
          "name": "remove_user",
          "args": {
            "user_id": "<legacy-sha256-id>"
          }
        }
      ]
    }

After it is accepted, submit a second proposal to enroll the certificate under its DID.
Copy the user's existing ``user_data`` into the new action, if present:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_user",
          "args": {
            "cert": "<user-certificate-pem>",
            "id_format": "did:key",
            "user_data": {
              "role": "example"
            }
          }
        }
      ]
    }

Use the returned DID in subsequent ``set_user_data`` and ``remove_user`` actions and in any application data or policy that stores a user ID.
The user's existing private key and certificate can authenticate after the new enrollment is accepted, but requests may fail during the gap between removal and re-enrollment.
See :ref:`governance/open_network:Adding Users` for the standard proposal workflow.

Migrating a member
------------------

Before removing a member, record its certificate, member data, encryption public key (if it is a recovery member), and recovery role.
The ``remove_member`` action deletes that member record and its data.
Migrate members one at a time and ensure that removing a recovery member will not take the number of active recovery members below the service's recovery threshold; the constitution rejects such a removal.

First, submit and get approval for a proposal that removes the member using its legacy ID:

.. code-block:: json

    {
      "actions": [
        {
          "name": "remove_member",
          "args": {
            "member_id": "<legacy-sha256-id>"
          }
        }
      ]
    }

After it is accepted, submit a second proposal to enroll the certificate under its DID.
Restore the member data and, for a recovery member, its encryption public key and recovery role:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_member",
          "args": {
            "cert": "<member-certificate-pem>",
            "id_format": "did:key",
            "member_data": {
              "role": "example"
            },
            "encryption_pub_key": "<member-encryption-public-key-pem>",
            "recovery_role": "Owner"
          }
        }
      ]
    }

Omit ``encryption_pub_key`` and ``recovery_role`` for a member that is not a recovery member.
The re-enrolled member starts in the ``Accepted`` state and must acknowledge the current service state digest again before participating in governance.
If it is a recovery member, follow the recovery-share procedure for the newly enrolled member; do not assume recovery state transfers from the removed ID.
For DID-signed governance requests, pass ``--identity-id-format did:key`` to ``ccf_cose_sign1`` as described in :doc:`adding_member`.
