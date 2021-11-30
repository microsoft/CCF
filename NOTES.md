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

Either:

1. The receipt or its constituent parts are only ever produced, or released out of the enclave after commit happens.
    a. The contents of the signature Tx stay in enclave until commit
        - Memory usage
        - Complexity for the host, breaks send append entries as it exists
    b. The contents of the signature tx are temporarily encrypted when written out, and decrypted and re-written in place on commit.
        - deserialise complexity
        - only encrypt committable tx
2. The receipt contains an additional piece of evidence, produced or released after commit happens.
    a. A later signature
        TxID <- Sig1 = Sig([..TxID..]) <- Sig2([commit >= Sig1])
        Latency for producing receipt
        Can never get a receipt over the last transaction?
        Must be careful not to lose uncommitted proof during recovery -> seems fine
        TxID <- Sig(commit >= TxID) ? Doesn't bound commit latency. Lose provenance.
    b. Another signature
        - On demand Sig(commit >= TxID), not in the ledger: expensive, cache (efficient via view history for old values)? stable across catastrophic recoveries
        - Batch
            - Off ledger - different tradeoff, extra latency, less execution cost
            - On ledger - done by primary, least execution cost, even more latency
        Note: on ledger not necessary for recovery, because the members decide where they resume.
    c. A nonce
    Cheaper to produce, include digest in receipt (committment), release in the fullness of time on commit.
    TxDigest := Digest(Write Set) + Digest(User claims) + Digest(Commit Nonce/Secret [+ TxID])
    Commit Nonce/Secret := Digest(Ledger Secret[TxID], TxID)
    The ledger alone doesn't tell you what's committed
    If Digest(Nonce) in ledger, then:
        - anything committable can be recovered.
        - possible to emit quasi receipt (with only digest and not nonce) -> not really a problem
    Else:
        - can't give quasi receipt
        - can't do public recovery!!!
    => Digest(Nonce) _must_ be in the ledger, or persisted somewhere

Terminology: execution receipt vs commit receipt

TxID in receipt
---------------

- How can a user trust a receipt is for a TxID?

a. bind at the leaf
    Include the TxID in a user separable way inside the TxDigest
b. bind at the signature
    Execution receipt could sign over (root + TxID), path offset to get TxID, ONLY for canonical receipt, otherwise need view history


Current preferred proposal
--------------------------

TxDigest := Digest(Digest(Write Set), Digest(User claims), Digest(Commit Nonce + TxID))
Commit Nonce/Secret := Digest(Ledger Secret[TxID], TxID)

TxDigest := Service Claims Digest + Digest(User claims)

Service Claims Digest A := Digest(Digest(Write Set), Digest(Commit Nonce), Digest(TxID))
Service Claims Digest A' := Digest(Digest(Write Set), Digest(Commit Nonce + TxID))
Service Claims Digest A'' := Digest(Digest(Write Set), Digest(Commit Nonce), TxID))
Service Claims Digest B := Digest(Write Set + Commit Nonce + TxID) -> NO