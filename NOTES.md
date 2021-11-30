User-defined claims
-------------------

Claims Digest := Digest(Claims)

Receipt := {
    Signature,
    Proof,
    Write Set Digest,
    Claims | Partial Claims
}

- Do the Claims Digests need to be stored in ledger?

Yes, to enable (in the case of offline claims) or faciliate (claims in KV) ledger integrity checks (audit, recovery).

- Do the Claims Digests need to be integrity protected?

Yes, to support external claim storage and stapling. In that case, we must return the Claims Digest to the user.

- Is it also nice for them to be?

Yes, because it yields early errors when replicating to other nodes. Otherwise delayed to next signature.

- Where do they go?

a. side by side with write set in ledger, outside GCM frame

No, because they must be integrity protected.

b. inside the GCM frame, in a separate section or domain

- Bump the version, and start encoding the version in the IV

We get to use the version, but perhaps risky? -> Talk to Antoine.

- is_snapshot bool -> enum/flags?

Version isn't used.

c. in a separate GCM frame

Useful to integrity check Write Set and Claims separately.

- when producing receipts: not useful

> check integrity of the Write Set: it goes in the receipt
> check integrity of the Claims Digest: yes, when claims stored externally
> very minor savings of GCM scope when claims are internal

- when ledger auditing/recovery: not useful

d. in the KV in a public table

No, because Leaf := Digest(Write Set, Claims), so the Write Set can stay opaque.

- What's the API?

Single Claims Digest + Helpers to derive one from blobs, collections of digests etc.

Committed receipts
------------------

- How can a user trust a receipt is for a committed state?

TxID in receipt
---------------

- How can  user trust a receipt is for a TxID?