// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT

#include "kv/encryptor.h"

#include "crypto/openssl/hash.h"
#include "kv/kv_types.h"
#include "kv/store.h"
#include "kv/test/stub_consensus.h"
#include "node/encryptor.h"
#include "node/ledger_secrets.h"

#include <doctest/doctest.h>
#undef FAIL
#include <random>
#include <string>

ccf::kv::ConsensusHookPtrs hooks;
using StringString = ccf::kv::Map<std::string, std::string>;

void commit_one(ccf::kv::Store& store, StringString& map)
{
  auto tx = store.create_tx();
  auto m = tx.rw(map);
  m->put("key", "value");
  REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
}

bool encrypt_round_trip(
  ccf::NodeEncryptor& encryptor,
  std::vector<uint8_t>& plain,
  ccf::kv::Version version)
{
  std::vector<uint8_t> aad;
  std::vector<uint8_t> header;
  std::vector<uint8_t> cipher(plain.size());
  std::vector<uint8_t> decrypted(plain.size());

  ccf::kv::Term term = 1;
  ccf::kv::Term ret_term = 0;
  encryptor.encrypt(plain, aad, header, cipher, {term, version});
  encryptor.decrypt(cipher, aad, header, decrypted, version, ret_term);

  return plain == decrypted && ret_term == term;
}

bool corrupt_serialised_tx(
  std::vector<uint8_t>& serialised_tx, std::vector<uint8_t>& value_to_corrupt)
{
  // This utility function corrupts a serialised transaction by changing one
  // byte of the public domain as specified by value_to_corrupt.
  std::vector<uint8_t> match_buffer;
  for (auto& i : serialised_tx)
  {
    if (i == value_to_corrupt[match_buffer.size()])
    {
      match_buffer.push_back(i);
      if (match_buffer.size() == value_to_corrupt.size())
      {
        i = 'X';
        LOG_DEBUG_FMT("Corrupting serialised public data");
        return true;
      }
    }
    else
    {
      match_buffer.clear();
    }
  }
  return false;
}

TEST_CASE("Simple encryption/decryption")
{
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  ccf::NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(10, 0x42);

  // Cannot encrypt before the very first KV version (i.e. 1)
  REQUIRE_THROWS_AS(
    encrypt_round_trip(encryptor, plain, 0),
    serialized::InsufficientSpaceException);

  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));

  ledger_secrets->set_secret(3, ccf::make_ledger_secret());
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));

  ledger_secrets->set_secret(5, ccf::make_ledger_secret());
  REQUIRE(encrypt_round_trip(encryptor, plain, 1));
  REQUIRE(encrypt_round_trip(encryptor, plain, 2));
  REQUIRE(encrypt_round_trip(encryptor, plain, 3));
  REQUIRE(encrypt_round_trip(encryptor, plain, 4));
  REQUIRE(encrypt_round_trip(encryptor, plain, 5));
  REQUIRE(encrypt_round_trip(encryptor, plain, 6));
}

TEST_CASE("Subsequent ciphers from same plaintext are different")
{
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  ccf::NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  ccf::kv::Version version = 10;
  ccf::kv::Term term = 1;

  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, {term, version});

  version++;
  encryptor.encrypt(
    plain, additional_data, serialised_header2, cipher2, {term, version});

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Ciphers at same seqno with different terms are different")
{
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  ccf::NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  ccf::kv::Version version = 10;
  ccf::kv::Term term = 1;

  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, {term, version});
  term++;
  encryptor.encrypt(
    plain, additional_data, serialised_header2, cipher2, {term, version});

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Ciphers at same seqno/term with and without snapshot are different")
{
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  ccf::NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> cipher2;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> serialised_header2;
  std::vector<uint8_t> additional_data; // No additional data
  ccf::kv::Version version = 10;
  ccf::kv::Term term = 1;

  encryptor.encrypt(
    plain,
    additional_data,
    serialised_header,
    cipher,
    {term, version},
    ccf::kv::EntryType::Snapshot);

  encryptor.encrypt(
    plain,
    additional_data,
    serialised_header2,
    cipher2,
    {term, version},
    ccf::kv::EntryType::WriteSet);

  // Ciphers are different because IV is different
  REQUIRE(cipher != cipher2);
  REQUIRE(serialised_header != serialised_header2);
}

TEST_CASE("Additional data")
{
  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  ccf::NodeEncryptor encryptor(ledger_secrets);

  std::vector<uint8_t> plain(128, 0x42);
  std::vector<uint8_t> cipher;
  std::vector<uint8_t> serialised_header;
  std::vector<uint8_t> additional_data(256, 0x10);
  ccf::kv::Version version = 10;
  ccf::kv::Term term = 1;

  // Encrypting plain at version 10
  encryptor.encrypt(
    plain, additional_data, serialised_header, cipher, {term, version});

  // Decrypting cipher at version 10
  std::vector<uint8_t> decrypted_cipher;
  REQUIRE(encryptor.decrypt(
    cipher,
    additional_data,
    serialised_header,
    decrypted_cipher,
    version,
    term));
  REQUIRE(plain == decrypted_cipher);

  // Tampering with additional data: decryption fails
  additional_data[100] = 0xAA;
  std::vector<uint8_t> decrypted_cipher2;
  REQUIRE_FALSE(encryptor.decrypt(
    cipher,
    additional_data,
    serialised_header,
    decrypted_cipher2,
    version,
    term));

  // Check we do not produce plain text if decryption fails
  REQUIRE(decrypted_cipher2.empty());
}

TEST_CASE("KV encryption/decryption")
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  StringString map("map");
  ccf::kv::Store primary_store;
  ccf::kv::Store backup_store;

  std::shared_ptr<ccf::LedgerSecrets> primary_ledger_secrets;
  std::shared_ptr<ccf::LedgerSecrets> backup_ledger_secrets;

  INFO("Initialise and communicate secrets to backup store");
  {
    // Initialise primary ledger secrets
    primary_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    primary_ledger_secrets->init();

    // Initialise backup ledger secrets from primary
    auto tx = primary_store.create_tx();
    backup_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    backup_ledger_secrets->init_from_map(primary_ledger_secrets->get(tx));

    auto primary_encryptor =
      std::make_shared<ccf::NodeEncryptor>(primary_ledger_secrets);
    auto backup_encryptor =
      std::make_shared<ccf::NodeEncryptor>(backup_ledger_secrets);

    primary_store.set_encryptor(primary_encryptor);
    primary_store.set_consensus(consensus);
    backup_store.set_encryptor(backup_encryptor);
  }

  INFO("Apply transaction to backup store");
  {
    commit_one(primary_store, map);
    REQUIRE(
      backup_store.deserialize(*consensus->get_latest_data())->apply() ==
      ccf::kv::ApplyResult::PASS);
  }

  INFO("Rekeys");
  {
    auto current_version = primary_store.current_version();
    for (size_t i = 1; i < 3; ++i)
    {
      // The primary and caught-up backup always encrypt/decrypt with the latest
      // available ledger secret
      auto new_ledger_secret = ccf::make_ledger_secret();

      // In practice, rekey is done via local commit hooks on the secrets table.
      auto ledger_secret_for_backup = new_ledger_secret;

      primary_ledger_secrets->set_secret(
        current_version + i, std::move(new_ledger_secret));

      commit_one(primary_store, map);

      backup_ledger_secrets->set_secret(
        current_version + i, std::move(ledger_secret_for_backup));

      REQUIRE(
        backup_store.deserialize(*consensus->get_latest_data())->apply() ==
        ccf::kv::ApplyResult::PASS);
    }
  }
}

TEST_CASE("Backup catchup from many ledger secrets")
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  StringString map("map");
  ccf::kv::Store primary_store;
  ccf::kv::Store backup_store;

  std::shared_ptr<ccf::LedgerSecrets> primary_ledger_secrets;
  std::shared_ptr<ccf::LedgerSecrets> backup_ledger_secrets;

  INFO("Initialise primary store and rekey ledger secrets a few times");
  {
    // Initialise primary ledger secrets
    primary_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    primary_ledger_secrets->init();
    auto primary_encryptor =
      std::make_shared<ccf::NodeEncryptor>(primary_ledger_secrets);
    primary_store.set_encryptor(primary_encryptor);
    primary_store.set_consensus(consensus);

    auto current_version = primary_store.current_version();
    for (size_t i = 2; i < 6; ++i)
    {
      commit_one(primary_store, map);
      primary_ledger_secrets->set_secret(
        current_version + i, ccf::make_ledger_secret());
    }
  }

  INFO("Initialise backup from primary");
  {
    // Just like in the join protocol, ledger secrets are passed to the joining
    // node in advance of KV store catch up
    auto tx = primary_store.create_tx();
    backup_ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
    backup_ledger_secrets->init_from_map(primary_ledger_secrets->get(tx));

    auto backup_encryptor =
      std::make_shared<ccf::NodeEncryptor>(backup_ledger_secrets);

    backup_store.set_encryptor(backup_encryptor);
  }

  // At this point, the backup has been given the ledger secrets but still
  // needs to catch up (similar to join protocol)
  INFO("Backup catch up over multiple rekeys");
  {
    auto next_entry = consensus->pop_oldest_entry();
    while (next_entry.has_value())
    {
      REQUIRE(
        backup_store.deserialize(*std::get<1>(next_entry.value()))->apply() ==
        ccf::kv::ApplyResult::PASS);

      auto tx_id = backup_store.current_txid();
      tx_id.seqno--;
      // While catching up, assume the backup rolls back (e.g. because of an
      // election)
      backup_store.rollback(tx_id, backup_store.commit_view());

      REQUIRE(
        backup_store.deserialize(*std::get<1>(next_entry.value()))->apply() ==
        ccf::kv::ApplyResult::PASS);

      next_entry = consensus->pop_oldest_entry();
    }
  }
}

TEST_CASE("KV integrity verification")
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  StringString map("map");
  ccf::kv::Store primary_store;
  ccf::kv::Store backup_store;

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(ledger_secrets);

  primary_store.set_encryptor(encryptor);
  primary_store.set_consensus(consensus);
  backup_store.set_encryptor(encryptor);

  auto tx = primary_store.create_tx();
  auto public_map = tx.rw<StringString>("public:public_map");
  auto private_map = tx.rw<StringString>("private_map");
  std::string pub_value = "pubv1";
  public_map->put("pubk1", pub_value);
  private_map->put("privk1", "privv1");
  auto rc = tx.commit();

  // Tamper with serialised public data
  auto latest_data = consensus->get_latest_data();
  REQUIRE(latest_data.has_value());
  std::vector<uint8_t> value_to_corrupt(pub_value.begin(), pub_value.end());
  REQUIRE(corrupt_serialised_tx(latest_data.value(), value_to_corrupt));

  auto r = backup_store.deserialize(latest_data.value());
  auto rr = r->apply();
  REQUIRE(rr == ccf::kv::ApplyResult::FAIL);
}

TEST_CASE("Encryptor rollback")
{
  StringString map("map");
  constexpr auto store_term = 2;
  ccf::kv::Store store;
  store.initialise_term(2);

  auto ledger_secrets = std::make_shared<ccf::LedgerSecrets>();
  ledger_secrets->init();
  auto encryptor = std::make_shared<ccf::NodeEncryptor>(ledger_secrets);
  store.set_encryptor(encryptor);

  commit_one(store, map);

  // Assumes tx at seqno 2 rekeys. Txs from seqno 3 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_secret(3, ccf::make_ledger_secret());

  commit_one(store, map);

  // Rollback store at seqno 1, discarding encryption key at 3
  store.rollback({store_term, 1}, store.commit_view());

  commit_one(store, map);

  // Assumes tx at seqno 3 rekeys. Txs from seqno 4 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_secret(4, ccf::make_ledger_secret());

  commit_one(store, map);
  commit_one(store, map);

  // Assumes tx at seqno 6 rekeys. Txs from seqno 7 will be encrypted with new
  // secret
  commit_one(store, map);
  ledger_secrets->set_secret(7, ccf::make_ledger_secret());

  commit_one(store, map);
  commit_one(store, map);
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}
