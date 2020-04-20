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
  class AbstractSeal
  {
  public:
    virtual ~AbstractSeal() {}
    virtual bool seal(
      kv::Version version, const std::vector<uint8_t>& data) = 0;
    virtual std::optional<std::vector<uint8_t>> unseal(
      const std::vector<uint8_t>& data) = 0;
  };

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
  private:
    std::shared_ptr<AbstractSeal> seal;

    kv::Version penultimate_version = kv::NoVersion;
    kv::Version latest_version = 0;

    void add_secret(kv::Version v, LedgerSecret&& secret, bool force_seal)
    {
      if (secrets_map.size() >= 1)
      {
        if (v > latest_version)
        {
          // There was already some secrets in the map, so the penultimate
          // secrets will be the current one, before the new secret is added
          penultimate_version = latest_version;
        }
        else
        {
          // If we are recovering secrets
          penultimate_version = v;
        }
      }

      if (seal && force_seal)
      {
        if (!seal->seal(v, secret.master))
        {
          throw std::logic_error(
            fmt::format("Ledger secret could not be sealed: {}", v));
        }
      }

      secrets_map.emplace(v, std::move(secret));

      if (v > latest_version)
      {
        latest_version = v;
      }
    }

  public:
    // Map of ledger secrets that are valid from a specific version to the
    // version of the next entry in the map. The last entry in the map is valid
    // for all subsequent versions.
    std::map<kv::Version, LedgerSecret> secrets_map; // TODO: Remove this

    struct VersionedLedgerSecret
    {
      kv::Version version;
      LedgerSecret secret;

      bool operator==(const VersionedLedgerSecret& other) const
      {
        return version == other.version && secret == other.secret;
      }
    };
    std::list<VersionedLedgerSecret> secrets_list;

    LedgerSecrets() = default;

    LedgerSecrets(std::shared_ptr<AbstractSeal> seal_) : seal(seal_) {}

    // Called when a node joins the network and get given the ledger secrets
    // since the beginning of time
    LedgerSecrets(
      LedgerSecrets&& ledger_secrets_, std::shared_ptr<AbstractSeal> seal_) :
      // secrets_map(std::move(ledger_secrets_.secrets_map)),
      secrets_list(std::move(ledger_secrets_.secrets_list)),
      seal(seal_)
    {
      // LOG_FAIL_FMT("Adding secrets at join time");
      // latest_version = 1;
      // LOG_FAIL_FMT("Latest version: {}", latest_version);
      // penultimate_version =
      // std::next(std::next(secrets_map.rbegin()))->first;
    }

    bool operator==(const LedgerSecrets& other) const
    {
      // return secrets_map == other.secrets_map;
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
      LOG_FAIL_FMT("Latest version: {}", latest_version);
      // return secrets_map.find(latest_version)->second;
      return secrets_list.back().secret;
    }

    std::optional<LedgerSecret> get_penultimate()
    {
      // if (penultimate_version == kv::NoVersion)
      // {
      //   return {};
      // }
      // return secrets_map.find(penultimate_version)->second;
      if (secrets_list.size() <= 1)
      {
        return {};
      }
      return std::next(secrets_list.rbegin())->secret;
    }

    // Called when a new secret needs to be given to the ledger secrets
    // - On recovery, to pass the historical secrets from the primary to the
    // backups
    // - On global commit in the encryptor (to be removed)
    bool set_secret(kv::Version v, const std::vector<uint8_t>& raw_secret)
    {
      // auto search = secrets_map.find(v);
      // if (search != secrets_map.end())
      // {
      //   return false;
      // }

      // add_secret(v, LedgerSecret(raw_secret), false);

      return true;
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

      LOG_FAIL_FMT("Size of list before restore {}", secrets_list.size());

      secrets_list.splice(secrets_list.begin(), std::move(restored_secrets));

      LOG_FAIL_FMT("Size of list after restore {}", secrets_list.size());
      LOG_FAIL_FMT("Size of other after restore {}", restored_secrets.size());
    }

    // // Called when sealed secrets need to be stored during recovery
    // std::vector<kv::Version> restore(const nlohmann::json& sealed_secrets)
    // {
    //   std::vector<kv::Version> restored_versions;

    //   for (auto it = sealed_secrets.begin(); it != sealed_secrets.end();
    //   ++it)
    //   {
    //     kv::Version v = std::stoi(it.key());

    //     auto search = secrets_map.find(v);
    //     if (search != secrets_map.end())
    //     {
    //       throw std::logic_error(fmt::format(
    //         "Cannot restore ledger secret that already exists: ", v));
    //     }

    //     auto s = seal->unseal(it.value());
    //     if (!s.has_value())
    //     {
    //       throw std::logic_error(
    //         fmt::format("Ledger secret could not be unsealed: {}", v));
    //     }

    //     LOG_DEBUG_FMT(
    //       "Ledger secret successfully unsealed at version {}", it.key());

    //     add_secret(v, LedgerSecret(s.value()), false);

    //     restored_versions.push_back(v);
    //   }

    //   return restored_versions;
    // }

    void seal_secret(kv::Version v)
    {
      if (!seal)
      {
        throw std::logic_error("No seal set to seal ledger secret");
      }

      for (auto const& s : secrets_list)
      {
        if (s.version == v)
        {
          if (!seal->seal(s.version, s.secret.master))
          {
            throw std::logic_error(fmt::format(
              "Ledger secret at version {} could not be sealed", v));
          }
          return;
        }
      }

      throw std::logic_error(
        fmt::format("Ledger secret to seal at version {} does not exist", v));
    }

    void seal_all()
    {
      for (auto const& s : secrets_list)
      {
        seal_secret(s.version);
      }
    }

    // Used when broadcast ledger secrets between primary and backups on
    // recovery
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
      return {};
    }
  };
}
