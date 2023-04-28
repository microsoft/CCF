import "@typespec/http";
import "@typespec/rest";
import "@azure-tools/typespec-azure-core";

@doc("A single step in a proposed change to the service.")
model Action {
  @doc("The name of action to perform. This should match an action defined in the service's constitution, so that it can be invoked by the `apply` function of the constitution if the proposal is accepted.")
  name: string;

  @doc("Arguments to modify the behaviour of this action. The schema is determined by the action implementation, and should be validated by a `validate` call in the constitution.")
  args: unknown;
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

@doc("Description of why governance execution failed.")
model FailureInfo {
  @doc("Error message describing reason for failure.")
  reason: string;

  @doc("Callstack showing where failure occurred, if available.")
  trace?: string;
}

@doc("Each key is a memberId, and the corresponding value is the result of their ballot.")
model MemberVotes is Record<boolean>;

@doc("Each key is a memberId, and the corresponding value explains why execution of their ballot failed.")
model VoteFailures is Record<FailureInfo>;

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

  @doc("If a proposal is not open, then this contains the result of each ballot when the proposal transitioned from open.")
  finalVotes?: MemberVotes;

  @doc("This will be populated with a description of any ballots which failed to execute.")
  voteFailures?: VoteFailures;

  @doc("If proposalState is Failure, then this will describe the proposal's failure.")
  failure?: FailureInfo;
}

@doc("The actions contained in a proposal, describing the proposal's changes.")
@TypeSpec.Rest.parentResource(Proposal)
model ProposalActions {
  @doc("A list of actions to apply. Each action is considered, in order, for both proposal and execution of the proposal. All actions are validated and, if the proposal is accepted, applied atomically.")
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

  @doc("The script to execute, returning the voter's support of this proposal.")
  @visibility("create")
  ballot: string;
}

@doc("A compact summary of the service's state up to a certain point in time, updated and signed by members to indicate their participation in and approval of the service.")
@TypeSpec.Rest.resource("stateDigests")
model StateDigest {
  @doc("Identifier for member this stateDigest applies to.")
  @visibility("read")
  @maxLength(64)
  @format("hex")
  @key
  memberId: string;

  @doc("Hex-encoding of SHA-256 hash of the root of the service's merkle tree. This should be signed by a new member and submitted as an ACK to mark that member as Active.")
  @maxLength(64)
  @format("hex")
  stateDigest: string;
}

@doc("TODO")
model CoseSignature {
  @doc("Content-type for all auditable member actions is application/cose, containing a CoseSign1 signature.")
  @TypeSpec.Http.header("Content-type")
  contentType: "application/cose";

  @doc("A raw CoseSign1 signature. See CCF docs for required headers and body schema: https://microsoft.github.io/CCF/main/use_apps/issue_commands.html#cose-sign1")
  @TypeSpec.Http.body
  body: bytes;
}

model CoseSigned<T = {}> extends CoseSignature {}

// @doc("Generic error")
// @error
// model MyError
// {
//   ...Azure.Core.Foundations.ErrorResponse;

//   @doc("TODO")
//   @TypeSpec.Http.statusCode
//   statusCode: 401;

//   @doc("TODO")
//   description: "WHAT";
// }

// alias CoseAuthedOperations = Azure.Core.ResourceOperations<
//   Azure.Core.Traits.NoConditionalRequests &
//     Azure.Core.Traits.NoRepeatableRequests &
//     Azure.Core.Traits.NoClientRequestId,
//   Azure.Core.Foundations.ErrorResponse | MyError
// >;

interface Proposals {
  // https://github.com/microsoft/CCF/issues/5230
  @doc("Submit a proposed change to the service. This will be assigned an ID by the service. Submitting the same signature (including signed COSE headers such as created_at) multiple times will be handled idempotently, returning a single created proposal (or an error if it is no longer available). Any change to the request body will be treated as a new, separate proposal.")
  propose is Azure.Core.StandardResourceOperations.ResourceCollectionAction<
    Proposal,
    CoseSigned<ProposalActions>,
    Proposal,
    TxIdWriteHeader
  >;

  @doc("Withdraw an existing proposal. Only the original proposer is permitted to withdraw.")
  withdraw is Azure.Core.StandardResourceOperations.ResourceCollectionAction<
    Proposal,
    CoseSigned,
    Proposal,
    TxIdWriteHeader
  >;

  @doc("Returns a summary of a single proposed change to the service.")
  getProposal is Azure.Core.StandardResourceOperations.ResourceRead<
    Proposal,
    TxIdReadHeader
  >;

  @doc("Returns all current proposed changes to the service. Note that non-open proposals (ie - those which have already been accepted, rejected, withdrawn, etc) are not returned.")
  // TODO: Remove nextLink
  listOpenProposals is Azure.Core.StandardResourceOperations.ResourceList<
    Proposal,
    TxIdReadHeader
  >;

  @doc("Returns actions contained in a proposal.")
  @TypeSpec.Rest.action("actions")
  @TypeSpec.Rest.actionSeparator("/")
  @TypeSpec.Http.get
  getActions is Azure.Core.StandardResourceOperations.ResourceAction<
    Proposal,
    {},
    ProposalActions,
    TxIdReadHeader
  >;
}

interface Ballots {
  @doc("Submit an executable ballot for a specific proposal. This may be as simple as `return true` to vote in favour, or contain reads from the KV and conditions on the proposal contents.")
  submit is Azure.Core.StandardResourceOperations.ResourceAction<
    Ballot,
    CoseSigned<Ballot>,
    Proposal,
    TxIdWriteHeader
  >;

  @doc("Returns a member's submitted ballot.")
  getBallot is Azure.Core.StandardResourceOperations.ResourceRead<
    Ballot,
    TxIdReadHeader
  >;
}

interface Acks {
  @doc("Request that this member's stateDigest is updated to a fresher value. Only this member may update their own stateDigest. Returns the refreshed value.")
  update is Azure.Core.StandardResourceOperations.ResourceAction<
    StateDigest,
    CoseSigned,
    StateDigest,
    TxIdWriteHeader
  >;

  @doc("Submit a signed acknowledgement of a recent digest of the service status, to transition the member to Active.")
  ack is Azure.Core.StandardResourceOperations.ResourceAction<
    StateDigest,
    CoseSigned<StateDigest>,
    TypeSpec.Http.NoContentResponse,
    TxIdWriteHeader
  >;

  @doc("Get the stateDigest assigned to the given member, which that member must sign to become active.")
  getStateDigest is Azure.Core.StandardResourceOperations.ResourceRead<
    StateDigest,
    TxIdReadHeader
  >;
}
