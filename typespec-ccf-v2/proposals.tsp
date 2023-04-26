import "@typespec/http";
import "@typespec/rest";
import "@azure-tools/typespec-azure-core";

@doc("A single step in a proposed change to the service.")
model Action {
  @doc("The name of action to perform. This should match an action defined in the service's constitution, so that it can be invoked by the `apply` function of the constitution if the proposal is accepted.")
  name: string;

  @doc("Arguments to modify the behaviour of this action. The schema is determined by the action implementation, and should be validated by a `validate` call in the constitution.")
  args: {};
}

@doc("Possible states for a proposal.")
enum ProposalState {
  @doc("Proposal is active and can be voted on.")
  Open,

  @doc("Proposal passed a successful vote and was enacted.")
  Accepted,

  @doc("Proposal was removed by proposing member. Will never be enacted.")
  Withdrawn,

  @doc("Proposal was rejected by vote. Will never be enacted.")
  Rejected,

  @doc("Proposal passed a successful vote, but its proposed actions failed. Will never be enacted.")
  Failed,

  @doc("Proposal was open when its semantics were potentially changed (code or constitution were modified), so it was automatically invalidated.")
  Dropped,
}

// Corresponds to ccf::jsgov::ProposalInfoSummary in C++
@doc("Description of a proposed change to the service.")
@TypeSpec.Rest.resource("proposals")
model Proposal {
  @key
  @doc("Unique ID assigned to this proposal at its submission, by the service.")
  @visibility("read")
  @maxLength(64)
  @format("hex")
  proposalId: string;

  @doc("ID of CCF member who signed and created this proposal.")
  @visibility("read")
  @maxLength(64)
  @format("hex")
  proposerId: string;

  @doc("Current state of this proposal.")
  proposalState: ProposalState;

  @doc("Count of how many ballots have been submitted for this proposal.")
  ballotCount: uint64;

  // TODO: votes, voteFailures, failure
}

@doc("The list of actions contained in a proposal.")
@TypeSpec.Rest.resource("details")
@TypeSpec.Rest.parentResource(Proposal)
model ProposalActions {
  @doc("TODO SINGLETON IS THIS VISIBLE?")
  @key("actionsSingleton")
  @visibility
  key: "actions";

  @visibility("read")
  @doc("A list of actions to apply. Each action is considered in-order for both proposal and execution of the proposal. All actions are validated and, if the proposal is accepted, applied atomically.")
  actions: Action[];
}

@doc("The source script of an executable vote from a member, regarding a proposed change to the service.")
@TypeSpec.Rest.resource("ballots")
@TypeSpec.Rest.parentResource(Proposal)
model Ballot {
  @doc("ID of CCF member who signed and submitted this ballot.")
  @visibility("read")
  @maxLength(64)
  @format("hex")
  @key
  memberId: string;

  @doc("TODO")
  @visibility("create")
  ballot: string;

  // TODO: More fields
}

@doc("TODO")
@TypeSpec.Rest.resource("stateDigests")
model StateDigest {
  @doc("Identifier for member this stateDigest applies to.")
  @visibility("read")
  @maxLength(64)
  @format("hex")
  @key
  memberId: string;

  @doc("TODO")
  @maxLength(64)
  @format("hex")
  stateDigest: string;
}

model CoseSigned<T = {}> {
  @doc("Content-type for all auditable member actions is application/cose, containing a CoseSign1 signature.")
  @TypeSpec.Http.header("Content-type")
  contentType: "application/cose";

  @doc("A raw CoseSign1 signature. The required protected headers and content schema will vary by action.")
  @TypeSpec.Http.body
  body: bytes;
}

interface Proposals {
  @doc("Submit a proposed change to the service. This will be assigned an ID by the service. Idempotence is based on the signed proposal body - submitting identical signed proposals multiple times will only create a single proposal on the server, unless sufficient time has passed (since the `created_at` signed COSE header), in which case the submission is stale and will return an error.")
  @TypeSpec.Http.route("proposals")
  propose is Azure.Core.StandardResourceOperations.ResourceCollectionAction<
    Proposal,
    CoseSigned<ProposalActions>,
    Proposal
  >;

  @doc("Returns a summary of a single proposed change to the service.")
  getProposal is Azure.Core.StandardResourceOperations.ResourceRead<Proposal>;

  @doc("Returns all current proposed changes to the service. Note that non-open proposals (ie - those which have already been accepted, rejected, withdrawn, etc) are not returned.")
  listOpenProposals is Azure.Core.StandardResourceOperations.ResourceList<Proposal>;

  @doc("Returns actions contained in a proposal.")
  getActions is Azure.Core.StandardResourceOperations.ResourceRead<ProposalActions>;
}

interface Ballots {
  @doc("Submit an executable ballot for a specific proposal. This may be as simple as `return true` to vote in favour, or contain reads from the KV and conditions on the proposal contents.")
  submit is Azure.Core.StandardResourceOperations.ResourceAction<
    Ballot,
    CoseSigned<Ballot>,
    Proposal
  >;

  @doc("Returns a member's submitted ballot.")
  getBallot is Azure.Core.StandardResourceOperations.ResourceRead<Ballot>;
}

interface Acks {
  @doc("TODO")
  update is Azure.Core.StandardResourceOperations.ResourceAction<
    StateDigest,
    CoseSigned,
    StateDigest
  >;

  @doc("Submit a signed acknowledgement of a recent digest of the service status, to transition the member to Active.")
  ack is Azure.Core.StandardResourceOperations.ResourceAction<
    StateDigest,
    CoseSigned<StateDigest>,
    TypeSpec.Http.NoContentResponse
  >;

  @doc("TODO")
  getStateDigest is Azure.Core.StandardResourceOperations.ResourceRead<StateDigest>;
}
