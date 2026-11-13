Migrating Users and Members to did:key
======================================

This guide describes how to move an existing user or member from its legacy SHA-256 ID to a ``did:key`` ID.
The ``did:key`` contains the identity public key, so enrollment and COSE authentication no longer require a certificate or certificate fingerprint.
CCF treats the two IDs as independent identities: it does not create an alias, change existing ledger entries, copy identity data between IDs, or check whether the same public key is enrolled under both formats.
Operators decide when to add the new identity and when to remove the old one.

Before migrating, upgrade every node in the service to a version that supports ``did:key`` IDs, and update the constitution to accept ``did_key`` in ``set_member`` and ``set_user``.
See :ref:`architecture/cryptography:Identity IDs` for compatibility and identity semantics.

Derive the new ID from the identity public key:

.. code-block:: bash

    $ python3 -m ccf.identity --public-key identity_pubk.pem --id-format did:key
    did:key:z...

For migration, ``--cert identity_cert.pem`` can instead extract the public key from a legacy certificate locally.
Use the resulting ``did:key`` for enrollment, signing, and recovery.

Migrating a user
----------------

Before removing the user, record its current user data, since the ``remove_user`` action deletes it.

Enroll the ``did:key`` with ``set_user``, copying the user's existing ``user_data``, if present.
Replace the placeholders and example data below with the saved identity information:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_user",
          "args": {
            "did_key": "<did:key>",
            "user_data": {
              "role": "example"
            }
          }
        }
      ]
    }

The user's existing private key can sign COSE requests with the new ID as soon as the proposal is accepted.
Use ``--signing-did-key`` instead of ``--signing-cert`` when creating COSE requests; their protected ``kid`` must identify the new enrollment.
Certificate-free requests require an endpoint with COSE authentication enabled.

Once clients and application data use the new ID, remove the legacy enrollment with ``remove_user``.
While both enrollments exist, they are separate users: TLS client authentication with the enrolled legacy certificate still identifies the caller by its legacy ID.
To switch over without a period where both IDs are enrolled, include ``remove_user`` and ``set_user`` in the same proposal.
Use the new ID in subsequent ``set_user_data`` and ``remove_user`` actions and in any application data or policy that stores a user ID.
See :ref:`governance/open_network:Adding Users` for the standard proposal workflow.

Migrating a member
------------------

Before removing a member, record its member data, encryption public key (if it is a recovery member), and recovery role, since the ``remove_member`` action deletes them.

Enroll the ``did:key`` with ``set_member``, restoring the member data and, for a recovery member, its encryption public key and recovery role.
Replace the placeholders and example data below with the saved identity information:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_member",
          "args": {
            "did_key": "<did:key>",
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
The new member starts in the ``Accepted`` state and must acknowledge the current service state digest before participating in governance.
For DID-signed governance requests, pass ``--signing-did-key <did:key>`` instead of ``--signing-cert`` to ``ccf_cose_sign1`` as described in :doc:`adding_member`.
If it is a recovery member, follow the recovery-share procedure for the newly enrolled member; do not assume recovery state transfers from the legacy ID.
Pass ``--member-did-key`` instead of ``--member-id-cert`` to ``submit_recovery_share.sh``.
The separate recovery encryption key is unchanged by this identity migration.

Once the new member is active, remove the legacy member with ``remove_member``.
The constitution rejects a removal that would take the number of active recovery members below the service's recovery threshold.

While both enrollments exist, the key holder is two members: each can vote on proposals, and each recovery member enrollment receives its own recovery share.
Consider the effect on the constitution's voting rules and on the recovery threshold, and keep this overlap short.
To avoid it, include ``remove_member`` followed by ``set_member`` in a single proposal.
The new member is then not active until it acknowledges the service state, so removing an active recovery member this way must not take the number of active recovery members below the recovery threshold.
Enough other active members must also remain to approve proposals while the new member is activated.
