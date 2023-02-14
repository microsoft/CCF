// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/signed_req.h"
#include "ccf/service/tables/acme_certificates.h"
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
#include "ccf/service/tables/users.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "kv/store.h"
#include "tables/backup_signatures.h"
#include "tables/config.h"
#include "tables/governance_history.h"
#include "tables/previous_service_identity.h"
#include "tables/resharing_types.h"
#include "tables/resharings.h"
#include "tables/secrets.h"
#include "tables/shares.h"
#include "tables/signatures.h"
#include "tables/snapshot_evidence.h"
#include "tables/submitted_shares.h"
#include "tables/view_change.h"

#include <memory>
#include <tuple>

namespace ccf
{
  inline std::shared_ptr<kv::Store> make_store(
    const ConsensusType& consensus_type)
  {
    return std::make_shared<kv::Store>(
      aft::replicate_type, aft::replicated_tables);
  }

  struct NetworkTables
  {
    std::shared_ptr<kv::Store> tables;

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

    inline auto get_all_member_tables() const
    {
      return std::make_tuple(
        member_certs, member_encryption_public_keys, member_info, member_acks);
    }

    //
    // User tables
    //
    const UserCerts user_certs = {Tables::USER_CERTS};
    const UserInfo user_info = {Tables::USER_INFO};

    inline auto get_all_user_tables() const
    {
      return std::make_tuple(user_certs, user_info);
    }

    //
    // Node tables
    //
    const CodeIDs node_code_ids = {Tables::NODE_CODE_IDS};
    const Nodes nodes = {Tables::NODES};
    const NodeEndorsedCertificates node_endorsed_certificates = {
      Tables::NODE_ENDORSED_CERTIFICATES};
    const ACMECertificates acme_certificates = {Tables::ACME_CERTIFICATES};
    const SnpHostDataMap host_data = {Tables::HOST_DATA};
    const SnpMeasurements snp_measurements = {Tables::NODE_SNP_MEASUREMENTS};
    const SnpUVMEndorsements snp_uvm_endorsements = {
      Tables::NODE_SNP_UVM_MEASUREMENTS};

    inline auto get_all_node_tables() const
    {
      return std::make_tuple(
        node_code_ids,
        nodes,
        node_endorsed_certificates,
        acme_certificates,
        host_data,
        snp_measurements,
        snp_uvm_endorsements);
    }

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

    inline auto get_all_governance_history_tables() const
    {
      return std::make_tuple(
        governance_history,
        cose_governance_history,
        proposals,
        proposal_info,
        cose_recent_proposals);
    }

    //
    // JS Generic tables
    //
    const Modules modules = {Tables::MODULES};
    const ModulesQuickJsBytecode modules_quickjs_bytecode = {
      Tables::MODULES_QUICKJS_BYTECODE};
    const ModulesQuickJsVersion modules_quickjs_version = {
      Tables::MODULES_QUICKJS_VERSION};
    const JSEngine js_engine = {Tables::JSENGINE};

    inline auto get_all_js_generic_tables() const
    {
      return std::make_tuple(
        modules, modules_quickjs_bytecode, modules_quickjs_version, js_engine);
    }

    //
    // JWT tables
    //
    const CACertBundlePEMs ca_cert_bundles = {Tables::CA_CERT_BUNDLE_PEMS};
    const JwtIssuers jwt_issuers = {Tables::JWT_ISSUERS};
    const JwtPublicSigningKeys jwt_public_signing_keys = {
      Tables::JWT_PUBLIC_SIGNING_KEYS};
    const JwtPublicSigningKeyIssuer jwt_public_signing_key_issuer = {
      Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER};

    inline auto get_all_jwt_tables() const
    {
      return std::make_tuple(
        ca_cert_bundles,
        jwt_issuers,
        jwt_public_signing_keys,
        jwt_public_signing_key_issuer);
    }

    //
    // Service tables
    //
    const Service service = {Tables::SERVICE};
    const PreviousServiceIdentity previous_service_identity = {
      Tables::PREVIOUS_SERVICE_IDENTITY};
    const Configuration config = {Tables::CONFIGURATION};
    const Constitution constitution = {Tables::CONSTITUTION};

    inline auto get_all_service_tables() const
    {
      return std::make_tuple(
        service, config, constitution, previous_service_identity);
    }

    // All builtin governance tables should be included here, so that wrapper
    // endpoints can be automatically generated for them
    inline auto get_all_builtin_governance_tables() const
    {
      return std::tuple_cat(
        get_all_member_tables(),
        get_all_user_tables(),
        get_all_node_tables(),
        get_all_governance_history_tables(),
        get_all_js_generic_tables(),
        get_all_jwt_tables(),
        get_all_service_tables());
    }

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
    const Resharings resharings = {Tables::RESHARINGS};

    // The signatures and serialised_tree tables should always be written to at
    // the same time so that the root of the tree in the signatures table
    // matches the serialised Merkle tree.
    const Signatures signatures = {Tables::SIGNATURES};
    const SerialisedMerkleTree serialise_tree = {
      Tables::SERIALISED_MERKLE_TREE};

    inline auto get_all_signature_tables() const
    {
      return std::make_tuple(signatures, serialise_tree);
    }

    inline auto get_all_internal_tables() const
    {
      return std::tuple_cat(
        std::make_tuple(
          secrets,
          snapshot_evidence,
          shares,
          encrypted_ledger_secrets,
          encrypted_submitted_shares),
        get_all_signature_tables());
    }

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::CFT) :
      tables(make_store(consensus_type))
    {}
  };
}