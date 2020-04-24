// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "kv/kv_types.h"
#include "tls/entropy.h"

#include <algorithm>
#include <nlohmann/json.hpp>

namespace ccf
{
  struct LedgerSecret
  {
    static constexpr auto MASTER_KEY_SIZE = crypto::GCM_SIZE_KEY;

    std::vector<uint8_t> master; // Referred to as "sd" in TR

    bool operator==(const LedgerSecret& other) const
    {
      return master == other.master;
    }

    LedgerSecret()
    {
      master = tls::create_entropy()->random(MASTER_KEY_SIZE);
    }

    LedgerSecret(const std::vector<uint8_t>& master_) : master(master_) {}
  };

  class LedgerSecrets
  {
  public:
    struct VersionedLedgerSecret
    {
      kv::Version version;
      LedgerSecret secret;

      bool operator==(const VersionedLedgerSecret& other) const
      {
        return version == other.version && secret == other.secret;
      }
    };
    // List of ledger secrets that are valid from a specific version to the
    // version of the next entry in the list. The last entry in the list is
    // valid for all subsequent versions.
    std::list<VersionedLedgerSecret> secrets_list;

    LedgerSecrets() = default;

    // Called when a node joins the network and get given the ledger secrets
    // since the beginning of time
    LedgerSecrets(const LedgerSecrets& ledger_secrets_) :
      secrets_list(ledger_secrets_.secrets_list)
    {}

    bool operator==(const LedgerSecrets& other) const
    {
      return secrets_list == other.secrets_list;
    }

    void init(kv::Version version = 1)
    {
      if (secrets_list.size() != 0)
      {
        throw std::logic_error("Ledger secrets have already been initialised!");
      }

      secrets_list.push_back({version, LedgerSecret()});
    }

    LedgerSecret get_latest()
    {
      if (secrets_list.size() == 0)
      {
        throw std::logic_error(
          "Could not retrieve latest ledger secret: no secret set");
      }
      return secrets_list.back().secret;
    }

    std::optional<LedgerSecret> get_penultimate()
    {
      if (secrets_list.size() <= 1)
      {
        return std::nullopt;
      }
      return std::next(secrets_list.rbegin())->secret;
    }

    void add_new_secret(kv::Version v, const LedgerSecret& ledger_secret)
    {
      secrets_list.push_back({v, ledger_secret});
    }

    void restore(std::list<VersionedLedgerSecret>&& restored_secrets)
    {
      if (
        secrets_list.size() >= 1 &&
        restored_secrets.back().version >= secrets_list.front().version)
      {
        throw std::logic_error(fmt::format(
          "Restored historical secrets should be before {}",
          secrets_list.front().version));
      }

      secrets_list.splice(secrets_list.begin(), std::move(restored_secrets));
    }

    // std::vector<kv::Version> restore_sealed(
    //   const nlohmann::json& sealed_secrets)
    // {
    //   std::list<VersionedLedgerSecret> restored_secrets;
    //   std::vector<kv::Version> restored_versions;

    //   for (auto it = sealed_secrets.begin(); it != sealed_secrets.end(); ++it)
    //   {
    //     auto s = seal->unseal(it.value());
    //     kv::Version v = std::stoi(it.key());
    //     if (!s.has_value())
    //     {
    //       throw std::logic_error(
    //         fmt::format("Ledger secret could not be unsealed: {}", v));
    //     }

    //     LOG_DEBUG_FMT("Ledger secret successfully unsealed at version {}", v);

    //     restored_secrets.push_back({v, LedgerSecret(s.value())});
    //     restored_versions.push_back(v);
    //   }

    //   restore(std::move(restored_secrets));

    //   return restored_versions;
    // }

    // void seal_secret(kv::Version v)
    // {
    //   if (!seal)
    //   {
    //     throw std::logic_error("No seal set to seal ledger secret");
    //   }

    //   for (auto const& s : secrets_list)
    //   {
    //     if (s.version == v)
    //     {
    //       if (!seal->seal(s.version, s.secret.master))
    //       {
    //         throw std::logic_error(fmt::format(
    //           "Ledger secret at version {} could not be sealed", v));
    //       }
    //       return;
    //     }
    //   }

    //   throw std::logic_error(
    //     fmt::format("Ledger secret to seal at version {} does not exist", v));
    // }

    // void seal_all()
    // {
    //   for (auto const& s : secrets_list)
    //   {
    //     seal_secret(s.version);
    //   }
    // }

    std::optional<LedgerSecret> get_secret(kv::Version v)
    {
      for (auto const& s : secrets_list)
      {
        if (s.version == v)
        {
          return s.secret;
        }
      }
      LOG_FAIL_FMT("Ledger secret at version {} does not exist", v);
      return std::nullopt;
    }
  };
}
