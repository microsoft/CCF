// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "consensus/aft/raft_tables.h"
#include "consensus/aft/request.h"
#include "consensus/aft/revealed_nonces.h"
#include "kv/store.h"
#include "tables/backup_signatures.h"
#include "tables/cert_bundles.h"
#include "tables/client_signatures.h"
#include "tables/code_id.h"
#include "tables/config.h"
#include "tables/constitution.h"
#include "tables/governance_history.h"
#include "tables/jwt.h"
#include "tables/members.h"
#include "tables/modules.h"
#include "tables/nodes.h"
#include "tables/proposals.h"
#include "tables/resharing_types.h"
#include "tables/resharings.h"
#include "tables/secrets.h"
#include "tables/service.h"
#include "tables/shares.h"
#include "tables/signatures.h"
#include "tables/snapshot_evidence.h"
#include "tables/submitted_shares.h"
#include "tables/users.h"
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

  struct Tables
  {
    // Service tables

    // Members
    static constexpr auto MEMBER_CERTS = "public:ccf.gov.members.certs";
    static constexpr auto MEMBER_ENCRYPTION_PUBLIC_KEYS =
      "public:ccf.gov.members.encryption_public_keys";
    static constexpr auto MEMBER_INFO = "public:ccf.gov.members.info";
    static constexpr auto MEMBER_ACKS = "public:ccf.gov.members.acks";

    // Users
    static constexpr auto USER_CERTS = "public:ccf.gov.users.certs";
    static constexpr auto USER_INFO = "public:ccf.gov.users.info";

    // Nodes identities and allowed code ids
    static constexpr auto NODES = "public:ccf.gov.nodes.info";
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
    static constexpr auto NODE_ENDORSED_CERTIFICATES =
      "public:ccf.gov.nodes.endorsed_certificates";

    // Service information
    static constexpr auto SERVICE = "public:ccf.gov.service.info";
    static constexpr auto CONFIGURATION = "public:ccf.gov.service.config";

    // JS applications, not service specific but writable by governance only
    static constexpr auto MODULES = "public:ccf.gov.modules";
    static constexpr auto MODULES_QUICKJS_BYTECODE =
      "public:ccf.gov.modules_quickjs_bytecode";
    static constexpr auto MODULES_QUICKJS_VERSION =
      "public:ccf.gov.modules_quickjs_version";
    static constexpr auto ENDPOINTS = "public:ccf.gov.endpoints";

    // TLS
    static constexpr auto CA_CERT_BUNDLE_PEMS =
      "public:ccf.gov.tls.ca_cert_bundles";

    // JWT issuers
    static constexpr auto JWT_ISSUERS = "public:ccf.gov.jwt.issuers";
    static constexpr auto JWT_PUBLIC_SIGNING_KEYS =
      "public:ccf.gov.jwt.public_signing_keys";
    static constexpr auto JWT_PUBLIC_SIGNING_KEY_ISSUER =
      "public:ccf.gov.jwt.public_signing_key_issuer";

    // Internal only
    static constexpr auto ENCRYPTED_PAST_LEDGER_SECRET =
      "public:ccf.internal.historical_encrypted_ledger_secret";
    static constexpr auto ENCRYPTED_LEDGER_SECRETS =
      "public:ccf.internal.encrypted_ledger_secrets";
    static constexpr auto SHARES = "public:ccf.internal.recovery_shares";
    static constexpr auto SUBMITTED_SHARES =
      "public:ccf.internal.encrypted_submitted_shares";
    static constexpr auto SNAPSHOT_EVIDENCE =
      "public:ccf.internal.snapshot_evidence";
    static constexpr auto SIGNATURES = "public:ccf.internal.signatures";
    static constexpr auto SERIALISED_MERKLE_TREE = "public:ccf.internal.tree";

    // Consensus
    static constexpr auto AFT_REQUESTS = "ccf.internal.consensus.requests";
    static constexpr auto NEW_VIEWS = "public:ccf.internal.consensus.new_views";
    static constexpr auto BACKUP_SIGNATURES =
      "public:ccf.internal.consensus.backup_signatures";
    static constexpr auto NONCES = "public:ccf.internal.consensus.nonces";

    // Governance
    static constexpr auto GOV_HISTORY = "public:ccf.gov.history";
    static constexpr auto CONSTITUTION = "public:ccf.gov.constitution";
    static constexpr auto PROPOSALS = "public:ccf.gov.proposals";
    static constexpr auto PROPOSALS_INFO = "public:ccf.gov.proposals_info";

    // Identity resharings
    static constexpr auto RESHARINGS = "public:ccf.internal.resharings";
  };

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
    NodeEndorsedCertificates node_endorsed_certificates;

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
    aft::RequestsMap bft_requests_map;
    BackupSignaturesMap backup_signatures_map;
    aft::RevealedNoncesMap revealed_nonces_map;
    NewViewsMap new_views_map;
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
      node_endorsed_certificates(Tables::NODE_ENDORSED_CERTIFICATES),
      service(Tables::SERVICE),
      secrets(Tables::ENCRYPTED_LEDGER_SECRETS),
      snapshot_evidence(Tables::SNAPSHOT_EVIDENCE),
      signatures(Tables::SIGNATURES),
      serialise_tree(Tables::SERIALISED_MERKLE_TREE),
      bft_requests_map(Tables::AFT_REQUESTS),
      backup_signatures_map(Tables::BACKUP_SIGNATURES),
      revealed_nonces_map(Tables::NONCES),
      new_views_map(Tables::NEW_VIEWS),
      resharings(Tables::RESHARINGS),
      constitution(Tables::CONSTITUTION)
    {}
  };
}