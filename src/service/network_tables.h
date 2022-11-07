// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/signed_req.h"
#include "ccf/service/tables/acme_certificates.h"
#include "ccf/service/tables/cert_bundles.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/constitution.h"
#include "ccf/service/tables/host_data.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/jwt.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/modules.h"
#include "ccf/service/tables/nodes.h"
#include "ccf/service/tables/proposals.h"
#include "ccf/service/tables/service.h"
#include "ccf/service/tables/users.h"
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "kv/store.h"
#include "tables/backup_signatures.h"
#include "tables/config.h"
#include "tables/governance_history.h"
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
    // Governance tables
    //
    MemberCerts member_certs;
    MemberPublicEncryptionKeys member_encryption_public_keys;
    MemberInfo member_info;

    Modules modules;
    ModulesQuickJsBytecode modules_quickjs_bytecode;
    ModulesQuickJsVersion modules_quickjs_version;
    JSEngine js_engine;
    CodeIDs node_code_ids;
    SnpHostDataMap host_data;
    MemberAcks member_acks;
    GovernanceHistory governance_history;
    COSEGovernanceHistory cose_governance_history;
    RecoveryShares shares;
    EncryptedLedgerSecretsInfo encrypted_ledger_secrets;
    EncryptedSubmittedShares encrypted_submitted_shares;
    Configuration config;

    CACertBundlePEMs ca_cert_bundles;

    JwtIssuers jwt_issuers;
    JwtPublicSigningKeys jwt_public_signing_keys;
    JwtPublicSigningKeyIssuer jwt_public_signing_key_issuer;

    //
    // User tables
    //
    UserCerts user_certs;
    UserInfo user_info;

    //
    // Node tables
    //
    Nodes nodes;
    NodeEndorsedCertificates node_endorsed_certificates;
    ACMECertificates acme_certificates;

    //
    // Internal CCF tables
    //
    Service service;
    Secrets secrets;
    SnapshotEvidence snapshot_evidence;

    // The signatures and serialised_tree tables should always be written to at
    // the same time so that the root of the tree in the signatures table
    // matches the serialised Merkle tree.
    Signatures signatures;
    SerialisedMerkleTree serialise_tree;

    //
    // bft related tables
    //
    Resharings resharings;

    // JS Constitution
    Constitution constitution;

    NetworkTables(const ConsensusType& consensus_type = ConsensusType::CFT) :
      tables(make_store(consensus_type)),
      member_certs(Tables::MEMBER_CERTS),
      member_encryption_public_keys(Tables::MEMBER_ENCRYPTION_PUBLIC_KEYS),
      member_info(Tables::MEMBER_INFO),
      modules(Tables::MODULES),
      modules_quickjs_bytecode(Tables::MODULES_QUICKJS_BYTECODE),
      modules_quickjs_version(Tables::MODULES_QUICKJS_VERSION),
      js_engine(Tables::JSENGINE),
      node_code_ids(Tables::NODE_CODE_IDS),
      host_data(Tables::HOST_DATA),
      member_acks(Tables::MEMBER_ACKS),
      governance_history(Tables::GOV_HISTORY),
      cose_governance_history(Tables::COSE_GOV_HISTORY),
      shares(Tables::SHARES),
      encrypted_ledger_secrets(Tables::ENCRYPTED_PAST_LEDGER_SECRET),
      encrypted_submitted_shares(Tables::ENCRYPTED_SUBMITTED_SHARES),
      config(Tables::CONFIGURATION),
      ca_cert_bundles(Tables::CA_CERT_BUNDLE_PEMS),
      jwt_issuers(Tables::JWT_ISSUERS),
      jwt_public_signing_keys(Tables::JWT_PUBLIC_SIGNING_KEYS),
      jwt_public_signing_key_issuer(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER),
      user_certs(Tables::USER_CERTS),
      user_info(Tables::USER_INFO),
      nodes(Tables::NODES),
      node_endorsed_certificates(Tables::NODE_ENDORSED_CERTIFICATES),
      acme_certificates(Tables::ACME_CERTIFICATES),
      service(Tables::SERVICE),
      secrets(Tables::ENCRYPTED_LEDGER_SECRETS),
      snapshot_evidence(Tables::SNAPSHOT_EVIDENCE),
      signatures(Tables::SIGNATURES),
      serialise_tree(Tables::SERIALISED_MERKLE_TREE),
      resharings(Tables::RESHARINGS),
      constitution(Tables::CONSTITUTION)
    {}
  };
}