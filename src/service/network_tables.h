// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoint.h"
#include "ccf/service/signed_req.h"
#include "ccf/service/tables/cert_bundles.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/constitution.h"
#include "ccf/service/tables/gov.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/modules.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/service/tables/service.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/tcb_verification.h"
#include "ccf/service/tables/users.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "ccf/service/tables/virtual_measurements.h"
#include "kv/store.h"
#include "service/tables/signing_identities.h"
#include "tables/config.h"
#include "tables/governance_history.h"
#include "tables/previous_service_identity.h"
#include "tables/secrets.h"
#include "tables/shares.h"
#include "tables/signatures.h"
#include "tables/snapshot_evidence.h"
#include "tables/submitted_shares.h"

#include <memory>

namespace ccf
{
  inline std::shared_ptr<ccf::kv::Store> make_store()
  {
    return std::make_shared<ccf::kv::Store>();
  }

  struct NetworkTables
  {
    std::shared_ptr<ccf::kv::Store> tables;

    //
    // Governance tables (public:ccf.gov.*)
    // Note that this only covers the builtin tables, with entries common to
    // many CCF services and modified by C++ code. Constitutions may extend this
    // with their own tables, and some services will not use all of these
    // tables.
    //

    //
    // Member tables
    //
    const MemberCerts member_certs = {Tables::MEMBER_CERTS};
    const MemberPublicEncryptionKeys member_encryption_public_keys = {
      Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS};
    const MemberInfo member_info = {Tables::MEMBER_INFO};
    const MemberAcks member_acks = {Tables::MEMBER_ACKS};

    //
    // User tables
    //
    const UserCerts user_certs = {Tables::USER_CERTS};
    const UserInfo user_info = {Tables::USER_INFO};

    //
    // Node tables
    //
    const CodeIDs node_code_ids = {Tables::NODE_CODE_IDS};
    const Nodes nodes = {Tables::NODES};
    const NodeEndorsedCertificates node_endorsed_certificates = {
      Tables::NODE_ENDORSED_CERTIFICATES};

    const VirtualHostDataMap virtual_host_data = {Tables::VIRTUAL_HOST_DATA};
    const VirtualMeasurements virtual_measurements = {
      Tables::NODE_VIRTUAL_MEASUREMENTS};

    const SnpHostDataMap host_data = {Tables::HOST_DATA};
    const SnpMeasurements snp_measurements = {Tables::NODE_SNP_MEASUREMENTS};
    const SNPUVMEndorsements snp_uvm_endorsements = {
      Tables::NODE_SNP_UVM_ENDORSEMENTS};
    const SnpTcbVersionMap snp_tcb_versions = {Tables::SNP_TCB_VERSIONS};

    //
    // History of governance, proposals, and ballots tables
    //
    const GovernanceHistory governance_history = {Tables::GOV_HISTORY};
    const COSEGovernanceHistory cose_governance_history = {
      Tables::COSE_GOV_HISTORY};
    const COSERecentProposals cose_recent_proposals = {
      Tables::COSE_RECENT_PROPOSALS};

    const jsgov::ProposalMap proposals = {jsgov::Tables::PROPOSALS};
    const jsgov::ProposalInfoMap proposal_info = {
      jsgov::Tables::PROPOSALS_INFO};

    //
    // JS Generic tables
    //
    const Modules modules = {Tables::MODULES};
    const ModulesQuickJsBytecode modules_quickjs_bytecode = {
      Tables::MODULES_QUICKJS_BYTECODE};
    const ModulesQuickJsVersion modules_quickjs_version = {
      Tables::MODULES_QUICKJS_VERSION};
    const InterpreterFlush interpreter_flush = {Tables::INTERPRETER_FLUSH};
    const JSEngine js_engine = {Tables::JSENGINE};
    const endpoints::EndpointsMap js_endpoints = {endpoints::Tables::ENDPOINTS};

    //
    // JWT tables
    //
    const CACertBundlePEMs ca_cert_bundles = {Tables::CA_CERT_BUNDLE_PEMS};
    const JwtIssuers jwt_issuers = {Tables::JWT_ISSUERS};
    const JwtPublicSigningKeysMetadata jwt_public_signing_keys_metadata = {
      Tables::JWT_PUBLIC_SIGNING_KEYS_METADATA};

    //
    // Service tables
    //
    const Service service = {Tables::SERVICE};
    const SigningIdentities signing_identities = {Tables::SIGNING_IDENTITIES};
    const PreviousServiceIdentity previous_service_identity = {
      Tables::PREVIOUS_SERVICE_IDENTITY};
    const PreviousServiceLastSignedRoot previous_service_last_signed_root = {
      Tables::PREVIOUS_SERVICE_LAST_SIGNED_ROOT};
    const PreviousServiceIdentityEndorsement
      previous_service_identity_endorsement = {
        Tables::PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT};
    const Configuration config = {Tables::CONFIGURATION};
    const Constitution constitution = {Tables::CONSTITUTION};

    //
    // Internal tables (public:ccf.internal.* and ccf.internal.*)
    //
    const Secrets secrets = {Tables::ENCRYPTED_LEDGER_SECRETS};
    const SnapshotEvidence snapshot_evidence = {Tables::SNAPSHOT_EVIDENCE};
    const RecoveryShares shares = {Tables::SHARES};
    const EncryptedLedgerSecretsInfo encrypted_ledger_secrets = {
      Tables::ENCRYPTED_PAST_LEDGER_SECRET};
    const EncryptedSubmittedShares encrypted_submitted_shares = {
      Tables::ENCRYPTED_SUBMITTED_SHARES};

    // The signatures and serialised_tree tables should always be written to at
    // the same time so that the root of the tree in the signatures table
    // matches the serialised Merkle tree.
    const Signatures signatures = {Tables::SIGNATURES};
    const CoseSignatures cose_signatures = {Tables::COSE_SIGNATURES};
    const SerialisedMerkleTree serialise_tree = {
      Tables::SERIALISED_MERKLE_TREE};

    NetworkTables() : tables(make_store()) {}
  };
}