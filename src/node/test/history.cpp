// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "node/history.h"

#include "ccf/app_interface.h"
#include "ccf/crypto/mldsa_key_pair.h"
#include "ccf/ds/locking.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/certs.h"
#include "crypto/openssl/hash.h"
#include "crypto/openssl/mldsa_support.h"
#include "ds/internal_logger.h"
#include "kv/kv_types.h"
#include "kv/null_encryptor.h"
#include "kv/store.h"
#include "kv/test/stub_consensus.h"
#include "service/tables/signatures.h"
#include "service/tables/signing_identities.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL

#include <atomic>
#include <exception>
#include <functional>
#include <optional>
#include <stop_token>
#include <thread>

using MapT = ccf::kv::Map<size_t, size_t>;

constexpr size_t certificate_validity_period_days = 365;
using namespace std::literals;
auto valid_from =
  ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

auto valid_to = ccf::crypto::compute_cert_valid_to_string(
  valid_from, certificate_validity_period_days);

class DummyConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;
  std::optional<ccf::kv::ApplyResult> last_apply_result = std::nullopt;
  std::exception_ptr last_apply_exception = nullptr;

  DummyConsensus(ccf::kv::Store* store_) : store(store_) {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
  {
    if (store)
    {
      REQUIRE(entries.size() == 1);
      last_apply_result = std::nullopt;
      last_apply_exception = nullptr;
      try
      {
        const auto result =
          store->deserialize(*std::get<1>(entries[0]))->apply();
        last_apply_result = result;
        return result != ccf::kv::ApplyResult::FAIL;
      }
      catch (const std::exception&)
      {
        last_apply_exception = std::current_exception();
        return false;
      }
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::FirstBackupNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }
};

// Signature transaction over the current root, carrying the signatures written
// by write_signatures
class CustomSignaturePendingTx : public ccf::kv::PendingTx
{
public:
  using WriteSignatures = std::function<void(
    ccf::kv::Tx& tx,
    const ccf::TxID& txid,
    const ccf::crypto::Sha256Hash& root)>;

private:
  ccf::TxID txid;
  ccf::kv::Store& store;
  ccf::kv::TxHistory& history;
  WriteSignatures write_signatures;

public:
  CustomSignaturePendingTx(
    ccf::TxID txid_,
    ccf::kv::Store& store_,
    ccf::kv::TxHistory& history_,
    WriteSignatures write_signatures_) :
    txid(txid_),
    store(store_),
    history(history_),
    write_signatures(std::move(write_signatures_))
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto tx = store.create_reserved_tx(txid);
    write_signatures(tx, txid, history.get_replicated_state_root());
    tx.wo<ccf::SerialisedMerkleTree>(ccf::Tables::SERIALISED_MERKLE_TREE)
      ->put(history.serialise_tree(txid.seqno - 1));
    return tx.commit_reserved();
  }
};

template <typename KeyPair>
ccf::CoseSignature sign_root(
  const KeyPair& key,
  const ccf::TxID& txid,
  const ccf::crypto::Sha256Hash& root)
{
  return ccf::cose::sign_ledger(
    key,
    ccf::crypto::kid_from_key(key.public_key_der()),
    0,
    "",
    "",
    txid.to_str(),
    root.h);
}

// A primary replicating to a backup, which verifies its signature transactions
struct SigningFixture
{
  std::shared_ptr<ccf::kv::NullTxEncryptor> encryptor =
    std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::crypto::ECKeyPairPtr node_kp = ccf::crypto::make_ec_key_pair();
  ccf::crypto::Pem node_cert =
    node_kp->self_sign("CN=Node", valid_from, valid_to);
  std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> service_kp =
    std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
      ccf::crypto::make_ec_key_pair());
  ccf::crypto::Pem service_cert =
    service_kp->self_sign("CN=Service", valid_from, valid_to);
  ccf::crypto::MLDSAKeyPairPtr pq_service_kp;
  std::optional<ccf::crypto::Pem> pq_service_cert = std::nullopt;

  ccf::kv::Store primary_store;
  ccf::kv::Store backup_store;
  std::shared_ptr<ccf::MerkleTxHistory> primary_history;
  std::shared_ptr<DummyConsensus> consensus;

  SigningFixture(ccf::crypto::MLDSAKeyPairPtr pq_service_kp_ = nullptr) :
    pq_service_kp(std::move(pq_service_kp_))
  {
    if (pq_service_kp != nullptr)
    {
      pq_service_cert =
        pq_service_kp->self_sign("CN=Service", valid_from, valid_to);
    }

    constexpr auto store_term = 2;
    primary_store.set_encryptor(encryptor);
    primary_history = std::make_shared<ccf::MerkleTxHistory>(
      primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
    primary_history->set_endorsed_certificate(node_cert);
    primary_history->set_service_signing_identity(
      service_kp, pq_service_kp, ccf::COSESignaturesConfig{});
    primary_store.set_history(primary_history);
    primary_store.initialise_term(store_term);

    backup_store.set_encryptor(encryptor);
    backup_store.set_history(std::make_shared<ccf::MerkleTxHistory>(
      backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp));
    backup_store.initialise_term(store_term);
    backup_store.set_consensus(std::make_shared<DummyConsensus>(nullptr));

    consensus = std::make_shared<DummyConsensus>(&backup_store);
    primary_store.set_consensus(consensus);

    commit([this](ccf::kv::Tx& tx) {
      ccf::NodeInfo node_info;
      node_info.encryption_pub_key = node_kp->public_key_pem();
      node_info.cert = node_cert;
      tx.wo<ccf::Nodes>(ccf::Tables::NODES)
        ->put(ccf::kv::test::PrimaryNodeId, node_info);
    });
  }

  void commit(const std::function<void(ccf::kv::Tx&)>& write)
  {
    auto tx = primary_store.create_tx();
    write(tx);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  // Service certificates, and the signing identity of every service key
  void publish_service_keys()
  {
    commit([this](ccf::kv::Tx& tx) {
      tx.wo<ccf::Service>(ccf::Tables::SERVICE)
        ->put(
          ccf::ServiceInfo{.cert = service_cert, .pq_cert = pq_service_cert});
      auto* identities =
        tx.wo<ccf::SigningIdentities>(ccf::Tables::SIGNING_IDENTITIES);
      identities->put(
        ccf::IdentityType::CLASSICAL,
        ccf::signing_identity_from_cert(service_cert));
      if (pq_service_cert.has_value())
      {
        identities->put(
          ccf::IdentityType::PQ,
          ccf::signing_identity_from_cert(pq_service_cert.value()));
      }
    });
  }

  // Result of applying the signature transaction on the backup, or nullopt if
  // applying it threw
  std::optional<ccf::kv::ApplyResult> emit_signature()
  {
    primary_history->emit_signature();
    return consensus->last_apply_result;
  }

  std::optional<ccf::kv::ApplyResult> emit_signature(
    CustomSignaturePendingTx::WriteSignatures write_signatures)
  {
    const auto txid = primary_store.next_txid();
    primary_store.commit(
      txid,
      std::make_unique<CustomSignaturePendingTx>(
        txid, primary_store, *primary_history, std::move(write_signatures)),
      true);
    return consensus->last_apply_result;
  }
};

TEST_CASE("Check signature verification")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  std::shared_ptr<ccf::kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  ccf::kv::Store backup_store;
  backup_store.set_encryptor(encryptor);
  std::shared_ptr<ccf::kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  backup_store.set_history(backup_history);
  backup_store.initialise_term(store_term);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);
  ccf::Signatures signatures(ccf::Tables::SIGNATURES);

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);

  std::shared_ptr<ccf::kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  INFO("Write certificates");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = node_kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(ccf::kv::test::PrimaryNodeId, ni);

    auto stx = txs.rw(service);
    auto service_info = ccf::ServiceInfo{
      .cert = service_kp->self_sign("CN=Service", valid_from, valid_to)};
    stx->put(service_info);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Issue signature, and verify successfully on backup");
  {
    primary_history->emit_signature();
    REQUIRE(backup_store.current_version() == 2);
  }

  INFO("Verify signatures after appending one unsigned transaction");
  {
    MapT table("public:table");
    auto tx = primary_store.create_tx();
    tx.rw(table)->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(backup_store.current_version() == 3);
    REQUIRE_FALSE(
      backup_history->verify_root_signatures(backup_store.current_version()));
  }

  INFO("Issue a bogus signature, rejected by verification on the backup");
  {
    auto txs = primary_store.create_tx();
    auto sigs = txs.rw(signatures);
    ccf::PrimarySignature bogus(ccf::kv::test::PrimaryNodeId, 0);
    bogus.sig = std::vector<uint8_t>(256, 1);
    sigs->put(bogus);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  }
}

TEST_CASE("Check signature verification with the signing identities table")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());
  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  auto primary_history = std::make_shared<ccf::MerkleTxHistory>(
    primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  ccf::kv::Store backup_store;
  backup_store.set_encryptor(encryptor);
  auto backup_history = std::make_shared<ccf::MerkleTxHistory>(
    backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_store.set_history(backup_history);
  backup_store.initialise_term(store_term);
  backup_store.set_consensus(std::make_shared<DummyConsensus>(nullptr));

  auto consensus = std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);
  const auto service_cert =
    service_kp->self_sign("CN=Service", valid_from, valid_to);
  {
    auto tx = primary_store.create_tx();
    ccf::NodeInfo node_info;
    node_info.encryption_pub_key = node_kp->public_key_pem();
    node_info.cert = self_signed;
    tx.rw(nodes)->put(ccf::kv::test::PrimaryNodeId, node_info);
    tx.rw(service)->put(ccf::ServiceInfo{.cert = service_cert});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("An empty table falls back to the service certificate");
  primary_history->emit_signature();
  REQUIRE(consensus->last_apply_result == ccf::kv::ApplyResult::PASS_SIGNATURE);

  auto tx = primary_store.create_tx();
  auto* signing_identities =
    tx.rw<ccf::SigningIdentities>(ccf::Tables::SIGNING_IDENTITIES);

  SUBCASE("A published signing identity verifies")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      ccf::signing_identity_from_cert(service_cert));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    primary_history->emit_signature();
    REQUIRE(
      consensus->last_apply_result == ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  SUBCASE("A legacy public key entry verifies")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      {ccf::IdentityKind::X509_SPKI_DER, service_kp->public_key_der()});
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    primary_history->emit_signature();
    REQUIRE(
      consensus->last_apply_result == ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  SUBCASE("A signing identity for another key fails verification")
  {
    const auto other_key = ccf::crypto::make_ec_key_pair();
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      ccf::signing_identity_from_cert(
        other_key->self_sign("CN=Other", valid_from, valid_to)));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    primary_history->emit_signature();
    REQUIRE(consensus->last_apply_result == ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("A published signing identity verifies without service information")
  {
    signing_identities->put(
      ccf::IdentityType::CLASSICAL,
      ccf::signing_identity_from_cert(service_cert));
    tx.rw(service)->clear();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    primary_history->emit_signature();
    REQUIRE(
      consensus->last_apply_result == ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  SUBCASE("Missing service information fails verification without an entry")
  {
    tx.rw(service)->clear();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    primary_history->emit_signature();
    REQUIRE(consensus->last_apply_result == ccf::kv::ApplyResult::FAIL);
  }
}

TEST_CASE("Signing identity carries an ML-DSA key next to the classical key")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());
  auto pq_service_kp =
    ccf::crypto::make_mldsa_key_pair(ccf::crypto::MLDSAParameterSet::ML_DSA_65);
  const auto pq_public_key_der = pq_service_kp->public_key_der();
  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);
  const auto service_cert =
    service_kp->self_sign("CN=Service", valid_from, valid_to);
  const auto pq_service_cert =
    pq_service_kp->self_sign("CN=Service", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  auto primary_history = std::make_shared<ccf::MerkleTxHistory>(
    primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, pq_service_kp, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  INFO("The history keeps the ML-DSA key");
  const std::weak_ptr<ccf::crypto::MLDSAKeyPair> retained_pq_service_kp =
    pq_service_kp;
  pq_service_kp.reset();
  REQUIRE_FALSE(retained_pq_service_kp.expired());

  ccf::kv::Store backup_store;
  backup_store.set_encryptor(encryptor);
  auto backup_history = std::make_shared<ccf::MerkleTxHistory>(
    backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_store.set_history(backup_history);
  backup_store.initialise_term(store_term);
  backup_store.set_consensus(std::make_shared<DummyConsensus>(nullptr));

  auto consensus = std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);
  ccf::SigningIdentities signing_identities(ccf::Tables::SIGNING_IDENTITIES);
  {
    auto tx = primary_store.create_tx();
    ccf::NodeInfo node_info;
    node_info.encryption_pub_key = node_kp->public_key_pem();
    node_info.cert = self_signed;
    tx.rw(nodes)->put(ccf::kv::test::PrimaryNodeId, node_info);
    tx.rw(service)->put(
      ccf::ServiceInfo{.cert = service_cert, .pq_cert = pq_service_cert});
    auto* identities = tx.rw(signing_identities);
    identities->put(
      ccf::IdentityType::CLASSICAL,
      ccf::signing_identity_from_cert(service_cert));
    identities->put(
      ccf::IdentityType::PQ, ccf::signing_identity_from_cert(pq_service_cert));
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Both signatures are emitted and verified on the backup");
  primary_history->emit_signature();
  REQUIRE(consensus->last_apply_result == ccf::kv::ApplyResult::PASS_SIGNATURE);

  auto tx = backup_store.create_read_only_tx();
  auto* cose_signatures =
    tx.ro<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
  const auto classical_signature =
    cose_signatures->get(ccf::IdentityType::CLASSICAL);
  const auto pq_signature = cose_signatures->get(ccf::IdentityType::PQ);
  REQUIRE(classical_signature.has_value());
  REQUIRE(pq_signature.has_value());

  INFO("The signatures share their protected header except alg and kid");
  const auto classical =
    ccf::cose::decode_ccf_receipt(classical_signature.value(), false).phdr;
  const auto pq =
    ccf::cose::decode_ccf_receipt(pq_signature.value(), false).phdr;
  const auto kid_bytes = [](const std::string& kid) {
    return std::vector<uint8_t>(kid.begin(), kid.end());
  };
  REQUIRE(
    classical.alg ==
    ccf::cose::algorithm_for_curve(service_kp->get_curve_id()).alg);
  REQUIRE(
    classical.kid ==
    kid_bytes(ccf::crypto::kid_from_key(service_kp->public_key_der())));
  REQUIRE(pq.alg == ccf::cose::alg::ML_DSA_65);
  REQUIRE(pq.kid == kid_bytes(ccf::crypto::kid_from_key(pq_public_key_der)));
  REQUIRE(pq.vds == classical.vds);
  REQUIRE(pq.ccf.txid == classical.ccf.txid);
  REQUIRE(pq.cwt.iat == classical.cwt.iat);
  REQUIRE(pq.cwt.iss == classical.cwt.iss);
  REQUIRE(pq.cwt.sub == classical.cwt.sub);
}

TEST_CASE("Every COSE signature is verified with the identity of its type")
{
  if (!ccf::crypto::mldsa_supported())
  {
    return;
  }

  SigningFixture f(ccf::crypto::make_mldsa_key_pair(
    ccf::crypto::MLDSAParameterSet::ML_DSA_65));
  f.publish_service_keys();
  REQUIRE(f.emit_signature() == ccf::kv::ApplyResult::PASS_SIGNATURE);

  const auto sign_with = [&f](
                           ccf::kv::Tx& tx,
                           const ccf::TxID& txid,
                           const ccf::crypto::Sha256Hash& root,
                           bool with_pq_signature,
                           bool tamper_pq_signature = false) {
    auto* signatures = tx.wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
    signatures->put(
      ccf::IdentityType::CLASSICAL, sign_root(*f.service_kp, txid, root));
    if (with_pq_signature)
    {
      auto pq_signature = sign_root(*f.pq_service_kp, txid, root);
      if (tamper_pq_signature)
      {
        pq_signature.back() ^= 1;
      }
      signatures->put(ccf::IdentityType::PQ, pq_signature);
    }
  };

  SUBCASE("Signatures by both published keys verify")
  {
    REQUIRE(f.emit_signature([&](auto& tx, const auto& txid, const auto& root) {
      sign_with(tx, txid, root, true);
    }) == ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  SUBCASE("A tampered PQ signature fails verification")
  {
    REQUIRE(f.emit_signature([&](auto& tx, const auto& txid, const auto& root) {
      sign_with(tx, txid, root, true, true);
    }) == ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("A PQ signature by another key fails verification")
  {
    const auto other_cert = ccf::crypto::make_mldsa_key_pair(
                              ccf::crypto::MLDSAParameterSet::ML_DSA_65)
                              ->self_sign("CN=Service", valid_from, valid_to);
    f.commit([&](ccf::kv::Tx& tx) {
      tx.wo<ccf::Service>(ccf::Tables::SERVICE)
        ->put(ccf::ServiceInfo{.cert = f.service_cert, .pq_cert = other_cert});
      tx.wo<ccf::SigningIdentities>(ccf::Tables::SIGNING_IDENTITIES)
        ->put(
          ccf::IdentityType::PQ, ccf::signing_identity_from_cert(other_cert));
    });
    REQUIRE(f.emit_signature() == ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("A published PQ identity requires a PQ signature")
  {
    // The table still holds the PQ signature of the previous signature
    // transaction, and this transaction writes only a CLASSICAL one
    REQUIRE(f.emit_signature([&](auto& tx, const auto& txid, const auto& root) {
      sign_with(tx, txid, root, false);
    }) == ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("A PQ signature requires a published PQ identity")
  {
    f.commit([&](ccf::kv::Tx& tx) {
      tx.wo<ccf::Service>(ccf::Tables::SERVICE)
        ->put(ccf::ServiceInfo{.cert = f.service_cert});
      tx.wo<ccf::SigningIdentities>(ccf::Tables::SIGNING_IDENTITIES)
        ->remove(ccf::IdentityType::PQ);
    });
    REQUIRE(f.emit_signature() == ccf::kv::ApplyResult::FAIL);
  }
}

TEST_CASE("A published CLASSICAL identity requires a CLASSICAL COSE signature")
{
  SigningFixture f;
  const auto node_signature_only = [&f](
                                     ccf::kv::Tx& tx,
                                     const ccf::TxID& txid,
                                     const ccf::crypto::Sha256Hash& root) {
    tx.wo<ccf::Signatures>(ccf::Tables::SIGNATURES)
      ->put(ccf::PrimarySignature(
        ccf::kv::test::PrimaryNodeId,
        txid.seqno,
        txid.view,
        root,
        {},
        f.node_kp->sign_hash(root.h.data(), root.h.size()),
        f.node_cert));
  };

  SUBCASE("Without a published identity, a node signature suffices")
  {
    f.commit([&f](ccf::kv::Tx& tx) {
      tx.wo<ccf::Service>(ccf::Tables::SERVICE)
        ->put(ccf::ServiceInfo{.cert = f.service_cert});
    });
    REQUIRE(
      f.emit_signature(node_signature_only) ==
      ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  SUBCASE("With a published identity, a node signature alone fails")
  {
    f.publish_service_keys();
    REQUIRE(f.emit_signature() == ccf::kv::ApplyResult::PASS_SIGNATURE);
    REQUIRE(
      f.emit_signature(node_signature_only) == ccf::kv::ApplyResult::FAIL);
  }
}

TEST_CASE("Signatures of a type this build cannot verify stop replay")
{
  using RawCoseSignatures = ccf::ServiceMap<uint64_t, ccf::CoseSignature>;
  using RawSigningIdentities = ccf::ServiceMap<uint64_t, ccf::Identity>;
  constexpr uint64_t unknown_identity_type = 2;

  SigningFixture f;
  f.publish_service_keys();
  REQUIRE(f.emit_signature() == ccf::kv::ApplyResult::PASS_SIGNATURE);

  const auto require_unverifiable =
    [&f](const std::optional<ccf::kv::ApplyResult>& result) {
      REQUIRE_FALSE(result.has_value());
      REQUIRE(f.consensus->last_apply_exception != nullptr);
      REQUIRE_THROWS_AS(
        std::rethrow_exception(f.consensus->last_apply_exception),
        ccf::kv::UnverifiableSignatureType);
    };

  SUBCASE("A signature of an unknown identity type")
  {
    require_unverifiable(
      f.emit_signature([&](auto& tx, const auto& txid, const auto& root) {
        auto* signatures =
          tx.template wo<RawCoseSignatures>(ccf::Tables::COSE_SIGNATURES);
        signatures->put(
          static_cast<uint64_t>(ccf::IdentityType::CLASSICAL),
          sign_root(*f.service_kp, txid, root));
        signatures->put(unknown_identity_type, {1, 2, 3});
      }));
  }

  SUBCASE("A signing identity of an unknown identity type")
  {
    f.commit([&](ccf::kv::Tx& tx) {
      tx.wo<RawSigningIdentities>(ccf::Tables::SIGNING_IDENTITIES)
        ->put(
          unknown_identity_type,
          ccf::signing_identity_from_cert(f.service_cert));
    });
    require_unverifiable(f.emit_signature());
  }

  SUBCASE("A PQ signature, on a build without ML-DSA")
  {
    const auto result =
      f.emit_signature([&f](auto& tx, const auto& txid, const auto& root) {
        auto* signatures =
          tx.template wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
        signatures->put(
          ccf::IdentityType::CLASSICAL, sign_root(*f.service_kp, txid, root));
        signatures->put(ccf::IdentityType::PQ, {1, 2, 3});
      });
    if (ccf::crypto::mldsa_supported())
    {
      // Verifiable by this build, and rejected for lack of a published PQ
      // identity
      REQUIRE(result == ccf::kv::ApplyResult::FAIL);
    }
    else
    {
      require_unverifiable(result);
    }
  }
}

TEST_CASE("Check signing works across rollback")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto self_signed = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store primary_store;
  primary_store.set_encryptor(encryptor);
  constexpr auto store_term = 2;
  std::shared_ptr<ccf::kv::TxHistory> primary_history =
    std::make_shared<ccf::MerkleTxHistory>(
      primary_store, ccf::kv::test::PrimaryNodeId, *node_kp);
  primary_history->set_endorsed_certificate(self_signed);
  primary_history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  primary_store.set_history(primary_history);
  primary_store.initialise_term(store_term);

  ccf::kv::Store backup_store;
  std::shared_ptr<ccf::kv::TxHistory> backup_history =
    std::make_shared<ccf::MerkleTxHistory>(
      backup_store, ccf::kv::test::FirstBackupNodeId, *node_kp);
  backup_history->set_endorsed_certificate(self_signed);
  backup_history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  backup_store.set_history(backup_history);
  backup_store.set_encryptor(encryptor);
  backup_store.initialise_term(store_term);

  ccf::Nodes nodes(ccf::Tables::NODES);
  ccf::Service service(ccf::Tables::SERVICE);

  std::shared_ptr<ccf::kv::Consensus> consensus =
    std::make_shared<DummyConsensus>(&backup_store);
  primary_store.set_consensus(consensus);
  std::shared_ptr<ccf::kv::Consensus> null_consensus =
    std::make_shared<DummyConsensus>(nullptr);
  backup_store.set_consensus(null_consensus);

  INFO("Write certificates");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    ni.encryption_pub_key = node_kp->public_key_pem();
    ni.cert = self_signed;
    tx->put(ccf::kv::test::PrimaryNodeId, ni);

    auto stx = txs.rw(service);
    auto service_info = ccf::ServiceInfo{
      .cert = service_kp->self_sign("CN=Service", valid_from, valid_to)};
    stx->put(service_info);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto v1_proof = primary_history->get_proof(primary_store.current_version());

  INFO("Transaction that we will roll back");
  {
    auto txs = primary_store.create_tx();
    auto tx = txs.rw(nodes);
    ccf::NodeInfo ni;
    tx->put(ccf::kv::test::FirstBackupNodeId, ni);
    REQUIRE(txs.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  primary_store.rollback({store_term, 1}, primary_store.commit_view());

  INFO("Issue signature, and verify successfully on backup");
  {
    primary_history->emit_signature();
    REQUIRE(backup_store.current_version() == 2);
  }

  auto v2_proof = primary_history->get_proof(primary_store.current_version());

  INFO("Check that past & current proofs are ok");
  {
    REQUIRE(primary_history->verify_proof(v1_proof));
    REQUIRE(primary_history->verify_proof(v2_proof));
    REQUIRE(primary_history->verify_proof(primary_history->get_proof(1)));
  }

  INFO("Check merkle roots are updating");
  {
    auto primary_root = primary_history->get_replicated_state_root();
    auto pr_str = fmt::format("{}", primary_root);
    auto backup_root = backup_history->get_replicated_state_root();
    auto bk_str = fmt::format("{}", backup_root);

    REQUIRE(pr_str == bk_str);
  }
}

class CompactingConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;
  size_t count = 0;

  CompactingConsensus(ccf::kv::Store* store_) : store(store_) {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
  {
    for (auto& [version, data, committable, hooks] : entries)
    {
      count++;
      if (committable)
        store->compact(version);
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::View get_view(ccf::kv::Version version) override
  {
    return 2;
  }
};

class TestPendingTx : public ccf::kv::PendingTx
{
  ccf::TxID txid;
  ccf::kv::Store& store;
  MapT& other_table;

public:
  TestPendingTx(ccf::TxID txid_, ccf::kv::Store& store_, MapT& other_table_) :
    txid(txid_),
    store(store_),
    other_table(other_table_)
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto txr = store.create_reserved_tx(txid);
    auto txrv = txr.rw(other_table);
    txrv->put(0, 1);
    return txr.commit_reserved();
  }
};

TEST_CASE("Pending signatures retain their endorsed certificate")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto first_cert =
    node_kp->self_sign("CN=First Node", valid_from, valid_to);
  const auto second_cert =
    node_kp->self_sign("CN=Second Node", valid_from, valid_to);

  ccf::kv::Store store;
  store.set_encryptor(encryptor);
  store.set_consensus(consensus);

  auto history = std::make_shared<ccf::MerkleTxHistory>(
    store, ccf::kv::test::PrimaryNodeId, *node_kp);
  history->set_endorsed_certificate(first_cert);
  history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  store.set_history(history);

  constexpr auto store_term = 2;
  store.initialise_term(store_term);

  MapT table("public:table");
  const auto gap_txid = store.next_txid();

  history->emit_signature();
  REQUIRE(consensus->number_of_replicas() == 0);

  history->set_endorsed_certificate(second_cert);
  REQUIRE(
    store.commit(
      gap_txid,
      std::make_unique<TestPendingTx>(gap_txid, store, table),
      false) == ccf::kv::CommitResult::SUCCESS);

  auto tx = store.create_read_only_tx();
  auto signatures = tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES);
  const auto signature = signatures->get();
  REQUIRE(signature.has_value());
  REQUIRE(signature->cert == first_cert);

  std::atomic<bool> updater_started = false;
  std::jthread updater([&](std::stop_token stop_token) {
    updater_started.store(true, std::memory_order_release);
    while (!stop_token.stop_requested())
    {
      history->set_endorsed_certificate(first_cert);
      history->set_endorsed_certificate(second_cert);
      std::this_thread::yield();
    }
  });

  while (!updater_started.load(std::memory_order_acquire))
  {
    std::this_thread::yield();
  }

  for (size_t i = 0; i < 32; ++i)
  {
    history->emit_signature();
  }

  updater.request_stop();
  updater.join();
}

TEST_CASE("Signatures are not emitted on demand until signing is enabled")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto service_kp = std::dynamic_pointer_cast<ccf::crypto::ECKeyPair_OpenSSL>(
    ccf::crypto::make_ec_key_pair());

  const auto node_cert = node_kp->self_sign("CN=Node", valid_from, valid_to);

  ccf::kv::Store store;
  store.set_encryptor(encryptor);
  store.set_consensus(consensus);

  // With an interval of 1, a single transaction makes try_emit_signature()
  // immediately eligible to sign
  constexpr size_t sig_tx_interval = 1;
  constexpr size_t sig_ms_interval = 1000;
  auto history = std::make_shared<ccf::MerkleTxHistory>(
    store,
    ccf::kv::test::PrimaryNodeId,
    *node_kp,
    sig_tx_interval,
    sig_ms_interval);
  history->set_endorsed_certificate(node_cert);
  history->set_service_signing_identity(
    service_kp, nullptr, ccf::COSESignaturesConfig{});
  store.set_history(history);

  constexpr auto store_term = 2;
  store.initialise_term(store_term);

  MapT table("public:table");

  auto get_signature = [&]() {
    auto tx = store.create_read_only_tx();
    return tx.ro<ccf::Signatures>(ccf::Tables::SIGNATURES)->get();
  };

  {
    auto tx = store.create_tx();
    tx.rw(table)->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }
  REQUIRE(consensus->number_of_replicas() == 1);
  REQUIRE(store.committable_gap() == 1);

  INFO("No signature before start_signature_emit_timer(), despite the gap");
  history->try_emit_signature();
  REQUIRE(consensus->number_of_replicas() == 1);
  REQUIRE_FALSE(get_signature().has_value());

  INFO("Signature emitted on demand once signing is enabled");
  history->start_signature_emit_timer();
  history->try_emit_signature();
  REQUIRE(consensus->number_of_replicas() == 2);
  REQUIRE(store.committable_gap() == 0);
  const auto signature = get_signature();
  REQUIRE(signature.has_value());
  REQUIRE(signature->cert == node_cert);
}

struct PausedSignatureCommit
{
  ccf::ds::Mutex lock;
  ccf::ds::ConditionVariable reserved_tx_created_cv;
  ccf::ds::ConditionVariable resume_cv;
  bool reserved_tx_created CCF_GUARDED_BY(lock) = false;
  bool resume CCF_GUARDED_BY(lock) = false;
};

class PausedReservedSignatureTx : public ccf::kv::PendingTx
{
  ccf::TxID txid;
  ccf::kv::Store& store;
  ccf::Signatures signatures;
  ccf::SerialisedMerkleTree serialised_tree;
  PausedSignatureCommit& paused;

public:
  PausedReservedSignatureTx(
    ccf::TxID txid_, ccf::kv::Store& store_, PausedSignatureCommit& paused_) :
    txid(txid_),
    store(store_),
    signatures(ccf::Tables::SIGNATURES),
    serialised_tree(ccf::Tables::SERIALISED_MERKLE_TREE),
    paused(paused_)
  {}

  ccf::kv::PendingTxInfo call() override
  {
    auto tx = store.create_reserved_tx(txid);
    auto sig = tx.rw(signatures);
    auto tree = tx.rw(serialised_tree);

    sig->put(ccf::PrimarySignature(ccf::kv::test::PrimaryNodeId, txid.seqno));
    tree->put({});

    {
      ccf::ds::MutexGuard guard(paused.lock);
      paused.reserved_tx_created = true;
    }
    paused.reserved_tx_created_cv.notify_one();

    ccf::ds::MutexGuard guard(paused.lock);
    paused.resume_cv.wait(
      guard, [this]() CCF_REQUIRES(paused.lock) { return paused.resume; });

    return tx.commit_reserved();
  }
};

TEST_CASE(
  "Batches containing but not ending on a committable transaction should not "
  "halt replication")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
  std::shared_ptr<CompactingConsensus> consensus =
    std::make_shared<CompactingConsensus>(&store);
  store.set_consensus(consensus);

  MapT table("public:table");
  MapT other_table("public:other_table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Batch of two, starting with a commitable");
  {
    auto rv = store.next_txid();

    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);

    store.commit(
      rv, std::make_unique<TestPendingTx>(rv, store, other_table), true);
    REQUIRE(consensus->count == 3);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 4);
  }
}

class RollbackConsensus : public ccf::kv::test::StubConsensus
{
public:
  ccf::kv::Store* store;
  size_t count = 0;
  ccf::kv::Version rollback_at;
  ccf::kv::Version rollback_to;

  RollbackConsensus(
    ccf::kv::Store* store_,
    ccf::kv::Version rollback_at_,
    ccf::kv::Version rollback_to_) :
    store(store_),
    rollback_at(rollback_at_),
    rollback_to(rollback_to_)
  {}

  bool replicate(const ccf::kv::BatchVector& entries, ccf::View view) override
  {
    for (auto& [version, data, committable, hook] : entries)
    {
      count++;
      if (version == rollback_at)
        store->rollback({view, rollback_to}, store->commit_view());
    }
    return true;
  }

  std::pair<ccf::View, ccf::SeqNo> get_committed_txid() override
  {
    return {2, 0};
  }

  ccf::SeqNo get_committed_seqno() override
  {
    return 0;
  }

  std::optional<ccf::kv::NodeId> primary() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::kv::NodeId id() override
  {
    return ccf::kv::test::PrimaryNodeId;
  }

  ccf::View get_view(ccf::SeqNo seqno) override
  {
    return 2;
  }

  ccf::View get_view() override
  {
    return 2;
  }
};

TEST_CASE(
  "Check that empty rollback during replicate does not cause replication halts")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 2);
  store.set_consensus(consensus);

  MapT table("public:table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 3);
  }
}

TEST_CASE(
  "Reserved signature tx returns no-replicate if rolled back before "
  "commit_reserved")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
  auto consensus = std::make_shared<ccf::kv::test::PrimaryStubConsensus>();
  store.set_consensus(consensus);
  constexpr auto store_term = 2;
  store.initialise_term(store_term);

  MapT table("public:table");

  INFO("Commit two normal transactions before emitting a signature");
  {
    auto tx = store.create_tx();
    auto* txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store.create_tx();
    auto* txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  REQUIRE(store.current_version() == 2);

  auto txid = store.next_txid();
  REQUIRE(txid == ccf::TxID(store_term, 3));

  PausedSignatureCommit paused;
  std::optional<ccf::kv::CommitResult> worker_result;

  std::thread worker([&]() {
    worker_result = store.commit(
      txid,
      std::make_unique<PausedReservedSignatureTx>(txid, store, paused),
      true);
  });

  {
    ccf::ds::MutexGuard guard(paused.lock);
    paused.reserved_tx_created_cv.wait(
      guard, [&paused]() CCF_REQUIRES(paused.lock) {
        return paused.reserved_tx_created;
      });
  }

  const auto new_term = store_term + 1;

  INFO(
    "Rollback after create_reserved_tx but before commit_reserved in a new "
    "term");
  store.rollback({store_term, 1}, new_term);
  REQUIRE(store.commit_view() == new_term);
  REQUIRE(store.current_txid() == ccf::TxID(store_term, 1));

  {
    ccf::ds::MutexGuard guard(paused.lock);
    paused.resume = true;
  }
  paused.resume_cv.notify_one();
  worker.join();

  REQUIRE(worker_result.has_value());
  REQUIRE(worker_result.value() == ccf::kv::CommitResult::FAIL_NO_REPLICATE);
  REQUIRE(store.current_txid() == ccf::TxID(store_term, 1));

  INFO("A normal transaction can still commit after the failed signature path");
  {
    auto tx = store.create_tx();
    auto* txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  REQUIRE(store.current_txid() == ccf::TxID(new_term, 2));
}

TEST_CASE(
  "Check that rollback during replicate does not cause replication halts")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);
  std::shared_ptr<RollbackConsensus> consensus =
    std::make_shared<RollbackConsensus>(&store, 2, 1);
  store.set_consensus(consensus);

  MapT table("public:table");

  INFO("Write first tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 1);
  }

  INFO("Write second tx, causing a rollback");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 2);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 2);
  }

  INFO("Single tx");
  {
    auto tx = store.create_tx();
    auto txv = tx.rw(table);
    txv->put(0, 3);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE(consensus->count == 3);
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}

TEST_CASE("COSE signature table holds one entry per identity")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  const ccf::CoseSignature ec384_sig{1, 2, 3};
  const ccf::CoseSignature mldsa65_sig{4, 5, 6};

  INFO("A table carrying two identities round-trips both");
  {
    auto tx = store.create_tx();
    auto* handle = tx.wo<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
    handle->put(ccf::IdentityType::CLASSICAL, ec384_sig);
    handle->put(ccf::IdentityType::PQ, mldsa65_sig);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store.create_read_only_tx();
    auto* handle = tx.ro<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);

    // A reader which only understands ECDSA still finds it, unaffected by
    // the presence of identities it does not know about.
    REQUIRE(handle->get(ccf::IdentityType::CLASSICAL) == ec384_sig);
    REQUIRE(handle->get(ccf::IdentityType::PQ) == mldsa65_sig);

    ccf::CoseSignatureMap read_back;
    handle->foreach([&read_back](const auto& identity_type, const auto& sig) {
      read_back.emplace(identity_type, sig);
      return true;
    });
    REQUIRE(read_back.size() == 2);
  }
}

TEST_CASE("CLASSICAL COSE signatures interoperate with the legacy singleton")
{
  using LegacyCoseSignatures = ccf::ServiceValue<ccf::CoseSignature>;
  ccf::kv::Store store;
  store.set_encryptor(std::make_shared<ccf::kv::NullTxEncryptor>());
  const ccf::CoseSignature legacy_signature{1, 2, 3};
  const ccf::CoseSignature keyed_signature{4, 5, 6};

  {
    auto tx = store.create_tx();
    tx.wo<LegacyCoseSignatures>(ccf::Tables::COSE_SIGNATURES)
      ->put(legacy_signature);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store.create_tx();
    auto* signatures = tx.rw<ccf::CoseSignatures>(ccf::Tables::COSE_SIGNATURES);
    REQUIRE(signatures->get(ccf::IdentityType::CLASSICAL) == legacy_signature);
    signatures->put(ccf::IdentityType::CLASSICAL, keyed_signature);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = store.create_read_only_tx();
    REQUIRE(
      tx.ro<LegacyCoseSignatures>(ccf::Tables::COSE_SIGNATURES)->get() ==
      keyed_signature);
  }
}

TEST_CASE("extract_cose_signatures skips removals")
{
  ccf::CoseSignatures::Write writes;
  writes[ccf::IdentityType::CLASSICAL] = ccf::CoseSignature{1, 2, 3};
  // A removal is recorded as an unset value, and must not be reported as a
  // signature.
  writes[ccf::IdentityType::PQ] = std::nullopt;

  const auto extracted = ccf::extract_cose_signatures(writes);
  REQUIRE(extracted.size() == 1);
  REQUIRE(
    extracted.at(ccf::IdentityType::CLASSICAL) == ccf::CoseSignature{1, 2, 3});
  REQUIRE_FALSE(extracted.contains(ccf::IdentityType::PQ));
}
