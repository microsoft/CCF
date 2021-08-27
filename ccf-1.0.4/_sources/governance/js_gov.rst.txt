JavaScript Governance
=====================

Constitution
------------

The constitution for a CCF service is implemented as a set of JS scripts. These scripts can be submitted at network startup as ``--constitution`` args to ``cchost``, or updated by a governance proposal. They will be concatenated into a single entry in the ``public:ccf.gov.constitution`` table, and should export 3 named functions:

    - ``validate``: This takes the raw body of a proposal and checks that this proposal is correctly formed. For instance it may parse the body as JSON, extract the list of proposed actions, and confirm that each action is known and has parameters matching the expected schema. This should not interact with the KV, and should operate purely on the given proposal.
    - ``resolve``: This takes a proposal and the votes (the results of ballot scripts) which have been submitted against it, and determines whether the proposal should be accepted or rejected. In the simple case this might simply accept proposals after a majority of members have voted in favour. It could also examine member data to give each member a different role or weight, or have different thresholds for each action. This has read-only access to the KV.
    - ``apply``: This takes a proposal which has been accepted by ``resolve``, and should make the proposed changes to the service's state. For instance if the proposal added a new user this should extract their cert and data from the proposal and write them to the appropriate KV tables. This has full read-write access to the KV.

Sample constitutions are available in the `src/runtime_config directory <https://github.com/microsoft/CCF/tree/main/src/runtime_config>`_, for instance the default implementation of ``apply`` which parses a JSON object from the proposal body, and then delegates the application of each action within the proposal to a named entry from ``actions.js``:

.. literalinclude:: ../../src/runtime_config/default/apply.js
    :language: js

There are also more involved examples such as ``veto/resolve.js``. This accepts proposals when a majority of members vote in favour, but also allows any single member to veto the proposal, marking it ``Rejected`` after a single vote against:

.. literalinclude:: ../../src/runtime_config/veto/resolve.js
    :language: js

Upgrading from Lua to JS
------------------------

The ``0.99.0`` release of CCF supports both Lua and JS governance. You should be able to upgrade to this release with your existing Lua governance tooling, then separately migrate to the JS governance, in preparation for the ``1.0`` release where Lua governance will be removed. To migrate, you will need to upgrade your constitution, your proposals, and your votes.

Upgrading constitution
~~~~~~~~~~~~~~~~~~~~~~

If you were using a Lua constitution provided by CCF then you can you can find an equivalent JS constitution in the CCF repo. All of these use the same list of proposable actions from ``default/actions.js``, and the same simple implementations of ``default/validate.js`` and ``default/apply.js``, but may have a custom ``resolve.js``. For instance if you were previously passing ``--gov-script <path/to/>gov_veto.lua`` you should now pass ``--constitution <path/to/>default/actions.js --constitution <path/to/>default/validate.js --constitution <path/to/>default/apply.js --constitution <path/to/>veto/resolve.js``. If you were using ``operator_gov.lua`` the resolve arg should instead be ``--constitution <path/to/>operator/resolve.js``. The sandbox also has a trivial ``resolve`` implementation which accepts all proposals in the same way as ``sanbox_gov.lua``. This is the version which will be installed in the CCF ``bin`` directory and used by ``sandbox.sh``.

If you have adapted these constitutions to write your own, you will need to port those adaptations to JS. The default constitutions should provide an example of how to do this. Please raise an issue on GitHub if you experience any problems.

Upgrading proposals and votes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

While the functionality of the proposals remains similar, the name and body schema of many proposals has been modified. Additionally the semantics may be slightly different as the new default proposal actions aim to be idempotent, so will execute successfully in some situations where they would previously have thrown (eg - adding a user who already exists). Similarly the format of the vote body has changed as it now expects a JS script exporting a ``vote`` function.

See `this Discussion <https://github.com/microsoft/CCF/discussions/2169#discussioncomment-373490>`_ for the mapping between proposal names in Lua and JS. The ``ccf.proposal_generator`` Python utility can be used to generate proposals. For instance:

.. code-block:: bash

    $ python -m ccf.proposal_generator --pretty-print set_user bob_cert.pem 
    [2021-04-06 11:10:00.194] SUCCESS | Writing proposal to ./set_user_proposal.json
    [2021-04-06 11:10:00.194] SUCCESS | Wrote vote to ./set_user_vote_for.json

    $ cat ./set_user_proposal.json 
    {
        "actions": [
            {
                "name": "set_user",
                "args": {
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIBrjCCATSgAwIBAgIUGCKB69cgr9N+EEMFvrVu6cInLvgwCgYIKoZIzj0EAwMw\nDjEMMAoGA1UEAwwDYm9iMB4XDTIxMDQwNjEwMDc0OFoXDTIyMDQwNjEwMDc0OFow\nDjEMMAoGA1UEAwwDYm9iMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAdgT5JJTVd0x\nyxphNeF8nccwu+Ro1lAEsKEdxzZhD461kv/ecOiqGtHnqlahiHxdQoiAhSfErjpx\n4bCQTCQeZkjZ/7FvOkS9St4uIwUf+/0CU0YxtVLGlSLRep0Sr5nZo1MwUTAdBgNV\nHQ4EFgQUOTRHQS8XOiS0Tf8yh6reB++Fzc8wHwYDVR0jBBgwFoAUOTRHQS8XOiS0\nTf8yh6reB++Fzc8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjBt\nkHZNFMtWT/79or93gasIuuKItFFjwyMYCMyDq2xUQyX2GtLhVfiVt0Te6hNeVE0C\nMQC7paiA2jrZjJ6qaFbDsJvrY7y9YioIrXA5txGgEEYhlPRDA2+5/5hG+bHLeQbi\noIU=\n-----END CERTIFICATE-----\n"
                }
            }
        ]
    }

    $ cat ./set_user_vote_for.json 
    {
        "ballot": "export function vote (rawProposal, proposerId) {\n  let proposal = JSON.parse(rawProposal);\n  if (!('actions' in proposal)) { return false; };\n  let actions = proposal['actions'];\n  if (actions.length !== 1) { return false; };\n  let action = actions[0];\n  if (!('name' in action)) { return false; };\n  if (action.name !== 'set_user') { return false; };\n  if (!('args' in action)) { return false; };\n  let args = action.args;\n  {\n    if (!('cert' in args)) { return false; };\n    let expected = \"-----BEGIN CERTIFICATE-----\\nMIIBrjCCATSgAwIBAgIUGCKB69cgr9N+EEMFvrVu6cInLvgwCgYIKoZIzj0EAwMw\\nDjEMMAoGA1UEAwwDYm9iMB4XDTIxMDQwNjEwMDc0OFoXDTIyMDQwNjEwMDc0OFow\\nDjEMMAoGA1UEAwwDYm9iMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEAdgT5JJTVd0x\\nyxphNeF8nccwu+Ro1lAEsKEdxzZhD461kv/ecOiqGtHnqlahiHxdQoiAhSfErjpx\\n4bCQTCQeZkjZ/7FvOkS9St4uIwUf+/0CU0YxtVLGlSLRep0Sr5nZo1MwUTAdBgNV\\nHQ4EFgQUOTRHQS8XOiS0Tf8yh6reB++Fzc8wHwYDVR0jBBgwFoAUOTRHQS8XOiS0\\nTf8yh6reB++Fzc8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNoADBlAjBt\\nkHZNFMtWT/79or93gasIuuKItFFjwyMYCMyDq2xUQyX2GtLhVfiVt0Te6hNeVE0C\\nMQC7paiA2jrZjJ6qaFbDsJvrY7y9YioIrXA5txGgEEYhlPRDA2+5/5hG+bHLeQbi\\noIU=\\n-----END CERTIFICATE-----\\n\";\n    if (JSON.stringify(args['cert']) !== JSON.stringify(expected)) { return false; };\n  }\n  return true;\n}"
    }

If you have custom tooling to generate proposals or votes, please use ``proposal_generator`` as a guide to the format these should now have. Note that if you have a custom constitution, then the format of the proposals themselves is also under your control.

Finally, these proposals and votes should be submitted to URL paths under ``/gov/proposals`` rather than ``/gov/proposals``.