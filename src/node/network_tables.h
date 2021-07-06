// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "backup_signatures.h"
#include "certs.h"
#include "client_signatures.h"
#include "code_id.h"
#include "config.h"
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "constitution.h"
#include "entities.h"
#include "governance_history.h"
#include "jwt.h"
#include "kv/store.h"
#include "members.h"
#include "modules.h"
#include "network_configurations.h"
#include "nodes.h"
#include "proposals.h"
#include "scripts.h"
#include "secrets.h"
#include "service.h"
#include "service_map.h"
#include "shares.h"
#include "signatures.h"
#include "snapshot_evidence.h"
#include "submitted_shares.h"
#include "users.h"
#include "values.h"

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
    MmeberPublicEncryptionKeys member_encryption_public_keys;
    MemberInfo member_info;

    Modules modules;
    ModulesQuickJsBytecode modules_quickjs_bytecode;
    ModulesQuickJsVersion modules_quickjs_version;
    CodeIDs node_code_ids;
    MemberAcks member_acks;
    GovernanceHistory governance_history;
    RecoveryShares shares;
    EncryptedLedgerSecretsInfo encrypted_ledger_secrets;
    SubmittedShares submitted_shares;
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
    // Node table
    //
    Nodes nodes;
    NetworkConfigurations network_configurations;

    //
    // Internal CCF tables
    //
    Service service;
    Values values;
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
    aft::RequestsMap bft_requests_map;
    BackupSignaturesMap backup_signatures_map;
    aft::RevealedNoncesMap revealed_nonces_map;
    NewViewsMap new_views_map;

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
      node_code_ids(Tables::NODE_CODE_IDS),
      member_acks(Tables::MEMBER_ACKS),
      governance_history(Tables::GOV_HISTORY),
      shares(Tables::SHARES),
      encrypted_ledger_secrets(Tables::ENCRYPTED_PAST_LEDGER_SECRET),
      submitted_shares(Tables::SUBMITTED_SHARES),
      config(Tables::CONFIGURATION),
      ca_cert_bundles(Tables::CA_CERT_BUNDLE_PEMS),
      jwt_issuers(Tables::JWT_ISSUERS),
      jwt_public_signing_keys(Tables::JWT_PUBLIC_SIGNING_KEYS),
      jwt_public_signing_key_issuer(Tables::JWT_PUBLIC_SIGNING_KEY_ISSUER),
      user_certs(Tables::USER_CERTS),
      user_info(Tables::USER_INFO),
      nodes(Tables::NODES),
      network_configurations(Tables::NETWORK_CONFIGURATIONS),
      service(Tables::SERVICE),
      values(Tables::VALUES),
      secrets(Tables::ENCRYPTED_LEDGER_SECRETS),
      snapshot_evidence(Tables::SNAPSHOT_EVIDENCE),
      signatures(Tables::SIGNATURES),
      serialise_tree(Tables::SERIALISED_MERKLE_TREE),
      bft_requests_map(Tables::AFT_REQUESTS),
      backup_signatures_map(Tables::BACKUP_SIGNATURES),
      revealed_nonces_map(Tables::NONCES),
      new_views_map(Tables::NEW_VIEWS),
      constitution(Tables::CONSTITUTION)
    {}
  };
}