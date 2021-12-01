# User-defined claims

## Requirements

- CCF is agnostic about claims format, in line with KV and request/response content type support.
- Receipt verification must not require parsing the Write Set
  - Would break format flexibility (CCF ledger frame encoding is fixed)
  - Would require re-design of private table to bake in confidential claims support
- Full support for ledgers containing a mix of transactions with and without user claims

```
Claims Digest := Digest(User Claims)

Receipt := {
    Signature over root of Proof,
    Proof,
    Write Set Digest,
    Claims | Partial Claims
}
```

## Do Claims Digests need to be stored in ledger?

**Yes**, to enable (in the case of offline claims) or facilitate (claims in KV) ledger integrity checks (audit, recovery). IOW, to preserve the ability of the ledger to be used standalone.

## Do Claims Digests need to be integrity protected?

**Yes**, to support external claim storage and stapling. In that case, the node must return the Claims Digest to the user, so it must have them stored.

## Is it also nice for them to be?

**Yes**, because it yields early errors when replicating to other nodes. Otherwise delayed to next signature. Not in principle a big problems, since receipts should not be issued during that time, but still.

## Where exactly are Claims Digests stored?

### Side by side with write set in ledger, outside GCM frame?

**No**, because they must be integrity protected.

### Inside the GCM frame, in a separate section or domain?

- Bump the ledger version, and start encoding the version in the IV. **Check this is sound with to Antoine.**
- is_snapshot bool -> enum/flags? Then version isn't used, still probably want IV coupling to protect old versions.

**Yes**

### In a separate GCM frame

Useful to check integrity of Write Set and Claims separately?

- when producing receipts: not useful
  - check integrity of the Write Set: it goes in the receipt
  - check integrity of the Claims Digest: yes, when claims stored externally
  - negligible savings of GCM scope when claims are internal, AEAD \* 2 fixed cost overhead
- when ledger auditing/recovery: not useful

**No**

### In the KV in a public table

**No**, because `Leaf := Digest(Write Set, Claims)`, so the Write Set can stay opaque.

### What's the API?

Single Claims Digest + Helpers to derive digest from blobs, collections of digests etc.

# Commit receipts

Terminology: **Execution Receipt** vs **Commit Receipt**

`Commit Receipt := Execution Receipt + Evidence of Commit`

# How can a user trust a receipt is for a committed state?

## 1. The receipt or its constituent parts are only ever produced, or released out of the enclave after commit happens

### The contents of the signature Tx stay in enclave until commit?

- Memory usage
- Complexity for the host, breaks send append entries as range

**No**

### The contents of the signature tx are temporarily encrypted when written out, and decrypted and re-written in place on commit.

- Require new SendAppendEntriesSigned, with a key tagging along
- Size/serialisation complexity

**No**

## 2. The receipt contains an additional piece of evidence, produced or released after commit happens.

### - A later signature

`TxID <- Sig1 = Sig([..TxID..]) <- Sig2([commit >= Sig1])`

- Latency for producing receipt
- Can never get a receipt over the last transaction.
- Must be careful not to lose uncommitted proof during recovery, seems fine.

**No**

`TxID <- Sig(commit >= TxID)`? Doesn't bound commit latency. Lose provenance. **Also No**

### - Another signature

- On demand `Sig(commit >= TxID)`, not in the ledger: expensive, cache (efficient via view history for old values)? Stable across catastrophic recoveries.
- Batch - Off ledger - different tradeoff, extra latency, less execution cost - On ledger - done by primary, least execution cost, even more latency
  Note: on ledger not necessary for recovery, because the members decide where they resume.

**Can work, but expensive**

### - A Nonce/Secret

Cheap to produce, include digest in receipt (committment), release in the fullness of time on commit.

```
TxDigest := Digest(Write Set) + Digest(User claims) + Digest(Commit Nonce/Secret [+ TxID])
Commit Nonce/Secret := Digest(Ledger Secret[TxID], TxID)
```

Note: ledger alone doesn't tell you what's committed. Need a receipt (or a snapshot).
Doesn't seem like a big problem, if service is live, can ask for receipt. If not, members decide, persistence is meaningless and provenance can still be checked.

If `Digest(Nonce)` in ledger, then:

- anything committable can be recovered.
- possible to emit quasi receipt (with only digest and not nonce) -> not really a problem, verifiers have to stick to algorithm

Else:

- can't give quasi receipt
- but can't do public recovery or verify offline
  => Digest(Nonce) _must_ be in the ledger, or persisted somewhere

**Seems best, simple and low overhead**

#### What goes in the nonce?

- `Commit Nonce/Secret := Digest(Ledger Secret[TxID], TxID)`

Granular, unique per-Tx.

- `Commit Nonce/Secret := Digest(Ledger Secret[TxID@Previous signature], TxID@Previous signature)`

Same nonce for all transactions between `Sig` and `next(Sig)` => fewer nonces if we decide to store them.

But more difficult for a node to derive the nonce, must find signature that immediately precedes transaction. Unless we tag each Tx with the TxID of the previous signature. Or tag the TxID in the next signature, but then there's no provenance.

Intuition of difficulties around rekey, but no obvious counter-example.

#### Can the nonce go in the ledger?

To make sure the ledger alone is enough to produce commit receipts (assuming transparent user claims!), we could store the nonces in either their own transaction, or a signature, from time to time.

It must not be a signature, signatures can only contain a signature!

If we store the nonces, having them per signature rather than per transaction may be attractive.

But storing the nonces in a separate Tx generates a constant stream of transactions, the "Treadmill problem".

If we batch, we must batch per signature because:

- we can't commit between signatures! anything more precise is wasteful of space.
- not batching every signature potentially delays commit reveal/receipt.

# TxID in receipt

## How can a user trust a receipt is for a specific TxID?

1. Bind at the leaf: include the TxID in a user separable way inside the TxDigest (ie. not in the WriteSet) **Yes**
2. Bind at the signature: execution receipt could sign over (root + TxID), path offset to get TxID, ONLY for canonical receipt, otherwise need view history. **No**

# Preferred direction summary

## Top-level

```
User Claims Digest := Digest(User Claims)
TxDigest := Digest(Service Claims Digest + User Claims Digest)

Service Claims Digest A := Digest(Digest(Write Set), Digest(Commit Nonce), Digest(TxID))
Service Claims Digest B := Digest(Digest(Write Set), Digest(Commit Nonce + TxID))
Service Claims Digest C := Digest(Digest(Write Set), Digest(Commit Nonce), TxID))

or

TxDigest := Digest(Digest(Write Set), Digest(User claims), Digest(Commit Nonce/Secret + TxID))
```

## Commit evidence

```
Commit Nonce/Secret := Digest(Ledger Secret[TxID], TxID)
```

Easy to derive, requires no storage.
