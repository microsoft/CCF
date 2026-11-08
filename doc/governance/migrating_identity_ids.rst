Migrating Users and Members to did:key
======================================

This guide describes how to move an existing user or member from its legacy SHA-256 ID to a ``did:key`` ID.
The DID contains the identity public key, so enrollment and COSE authentication no longer require a certificate or certificate fingerprint.
Changing an enrolled ID is not an in-place operation: CCF does not create an alias, change existing ledger entries, or copy identity data between IDs.

Before migrating, upgrade every node in the service to a version that supports ``did:key`` IDs.
Update the constitution to include the ordered removal-and-enrollment validation used in this guide.
See :ref:`architecture/cryptography:Identity IDs` for compatibility and identity semantics.

Derive the new ID from the identity public key:

.. code-block:: bash

    $ python3 -m ccf.identity --public-key identity_pubk.pem --id-format did:key
    did:key:z...

For migration, ``--cert identity_cert.pem`` can instead extract the public key from a legacy certificate locally.
Only the resulting ``did:key`` string is sent in the new enrollment action.
Neither ``cert`` nor ``id_format`` is accepted alongside ``did_key``.
The ID format is scoped to each role: the same public key may be enrolled as a member and a user, but cannot be enrolled in both formats at the same time within either role.
Group the removal and DID enrollment in a single proposal, with the removal action first.
The actions are applied in order within one transaction: either both succeed, or neither takes effect.
There is no externally visible gap between removal and re-enrollment, but the ID changes and a migrated member still needs to activate its new enrollment.
If the same public key has multiple legacy enrollments in one role, remove all of them before the DID enrollment action.

Migrating a user
----------------

Before removing the user, record its current user data and the certificate associated with its legacy ID.
The ``remove_user`` action deletes the user's certificate and user data, so include the saved user data when enrolling the DID identity.

Submit and get approval for a proposal containing ``remove_user`` followed by ``set_user``.
Copy the user's existing ``user_data`` into the new action, if present.
Replace the placeholders and example data below with the saved identity information:

.. code-block:: json

    {
      "actions": [
        {
          "name": "remove_user",
          "args": {
            "user_id": "<legacy-sha256-id>"
          }
        },
        {
          "name": "set_user",
          "args": {
            "did_key": "<canonical-did:key>",
            "user_data": {
              "role": "example"
            }
          }
        }
      ]
    }

Use the returned DID in subsequent ``set_user_data`` and ``remove_user`` actions and in any application data or policy that stores a user ID.
The user's existing private key can sign requests immediately after the proposal is accepted.
Use ``--signing-did-key`` instead of ``--signing-cert`` when creating COSE requests; their protected ``kid`` must identify the new enrollment.
Certificate-free requests require an endpoint with COSE authentication enabled.
See :ref:`governance/open_network:Adding Users` for the standard proposal workflow.

Migrating a member
------------------

Before removing a member, record its certificate, member data, encryption public key (if it is a recovery member), and recovery role.
The ``remove_member`` action deletes that member record and its data.
Migrate members one at a time and ensure that removing a recovery member will not take the number of active recovery members below the service's recovery threshold; the constitution rejects such a removal.
Atomic enrollment does not bypass this check, because the replacement member is not active until it acknowledges the service state.
If necessary, add and activate another recovery member before migrating.
Keep enough other active members to approve proposals while the migrated member is being reactivated.

Submit and get approval for one proposal containing ``remove_member`` followed by ``set_member``.
Restore the member data and, for a recovery member, its encryption public key and recovery role.
Replace the placeholders and example data below with the saved identity information:

.. code-block:: json

    {
      "actions": [
        {
          "name": "remove_member",
          "args": {
            "member_id": "<legacy-sha256-id>"
          }
        },
        {
          "name": "set_member",
          "args": {
            "did_key": "<canonical-did:key>",
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
For DID-signed governance requests, pass ``--signing-did-key <canonical-did:key>`` instead of ``--signing-cert`` to ``ccf_cose_sign1`` as described in :doc:`adding_member`.
Pass ``--member-did-key`` instead of ``--member-id-cert`` to ``submit_recovery_share.sh``.
The separate recovery encryption key is unchanged by this identity migration.
