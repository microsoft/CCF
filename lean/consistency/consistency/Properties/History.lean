module

public import consistency.Model

@[expose] public section

namespace consistency.Properties

open Model

/-- A response's payload, separated from its position in the external history. -/
structure Response where
  kind : TxType
  tx : TxContent
  observed : List TxContent
  txid : TxID
deriving DecidableEq, Repr

/-- Responses paired with zero-based history positions, preserving real-time order. -/
def responses (history : List Event) : List (Nat × Response) :=
  history.zipIdx.filterMap
    fun (event, index) =>
      match event with
      | .response kind tx observed txid => some (index, ⟨kind, tx, observed, txid⟩)
      | _ => none

/-- Requests paired with zero-based history positions. -/
def requests (history : List Event) : List (Nat × (TxType × TxContent)) :=
  history.zipIdx.filterMap
    fun (event, index) =>
      match event with
      | .request kind tx => some (index, kind, tx)
      | _ => none

/-- Status-event payloads, retaining repetitions. -/
def statuses (history : List Event) : List (TxID × Status) :=
  history.filterMap
    fun event =>
      match event with
      | .status txid status => some (txid, status)
      | _ => none

/-- Responses selected by transaction kind. -/
def responsesOf (history : List Event) (kind : TxType) : List (Nat × Response) :=
  (responses history).filter (fun response => response.2.kind == kind)

/-- A response counts as committed only when that exact ID has a committed status.
The retained index is the original response event, not the later status event. -/
def committedResponses (history : List Event) (kind : TxType) : List (Nat × Response) :=
  (responsesOf history kind).filter
    fun response =>
      (statusIDs history .committed).contains response.2.txid

/-- Requests whose matching response is explicitly known committed. -/
def committedRequests (history : List Event) (kind : TxType)
    : List (Nat × (TxType × TxContent)) :=
  (requests history).filter
    fun request =>
      request.2.1 == kind
      && (committedResponses history kind).any
          (fun response => response.2.tx == request.2.2)

/-- Lexicographic order on view, then sequence number. -/
def txIDStrictlyLessThan (left right : TxID) : Prop :=
  left.view < right.view ∨ (left.view = right.view ∧ left.seqno < right.seqno)

instance (left right : TxID) : Decidable (txIDStrictlyLessThan left right) :=
  inferInstanceAs
    (Decidable
      (left.view < right.view ∨ (left.view = right.view ∧ left.seqno < right.seqno)))

/-- Deduplicate response payloads, not their history positions, then sort.
These responses are ordered by transaction ID, not by client-observation order.
Equal-ID ties retain first-occurrence order; intended uniqueness rules out distinct ties. -/
def committedRwResponses (history : List Event) : List Response :=
  ((committedResponses history .rw).map Prod.snd).eraseDups.mergeSort
    (fun left right => decide (¬ txIDStrictlyLessThan right.txid left.txid))

end consistency.Properties
