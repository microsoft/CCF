// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "kv/kvtypes.h"
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
    std::vector<uint8_t> master; // Referred to as "sd" in TR

    bool operator==(const LedgerSecret& other) const
    {
      return master == other.master;
    }

    LedgerSecret(bool random = false)
    {
      if (random)
      {
        master = tls::create_entropy()->random(32);
      }
    }

    LedgerSecret(const std::vector<uint8_t>& ledger_master_) :
      master(ledger_master_)
    {}
  };

  class LedgerSecrets
  {
    // Map of secrets that are valid from a specific version to the version of
    // the next entry in the map. The last entry in the map is valid for all
    // subsequent versions.
    std::map<kv::Version, std::unique_ptr<LedgerSecret>> secrets_map;

    std::unique_ptr<AbstractSeal> seal;
    kv::Version current_version = 0;

    void add_secret(
      kv::Version v, std::unique_ptr<LedgerSecret>&& secret, bool force_seal)
    {
      if (seal && force_seal)
      {
        if (!seal->seal(v, secret->master))
        {
          throw std::logic_error(
            fmt::format("Ledger secret could not be sealed: {}", v));
        }
      }

      secrets_map.emplace(v, std::move(secret));
      current_version = std::max(current_version, v);
    }

  public:
    // Called on startup to generate fresh ledger secret
    LedgerSecrets(
      std::unique_ptr<AbstractSeal> seal_ = nullptr, bool force_seal = true) :
      seal(std::move(seal_))
    {
      // Generate fresh ledger encryption key
      auto new_secret = std::make_unique<LedgerSecret>(true);
      add_secret(1, std::move(new_secret), force_seal);
    }

    // Called when a node joins the network and get given the current ledger
    // secrets
    LedgerSecrets(
      kv::Version v,
      LedgerSecret& secret,
      std::unique_ptr<AbstractSeal> seal_ = nullptr,
      bool force_seal = true) :
      seal(std::move(seal_))
    {
      auto new_secret = std::make_unique<LedgerSecret>(secret);
      add_secret(v, std::move(new_secret), force_seal);
    }

    // Called when a backup is given past ledger secret via the store
    bool set_secret(kv::Version v, const std::vector<uint8_t>& secret)
    {
      auto search = secrets_map.find(v);
      if (search != secrets_map.end())
      {
        LOG_FAIL_FMT("Ledger secret at {} already exists", v);
        return false;
      }

      auto new_secret = std::make_unique<LedgerSecret>(secret);
      add_secret(v, std::move(new_secret), false);

      return true;
    }

    // Called when sealed secrets need to be stored during recovery
    std::vector<kv::Version> restore(const nlohmann::json& sealed_secrets)
    {
      std::vector<kv::Version> restored_versions;

      for (auto it = sealed_secrets.begin(); it != sealed_secrets.end(); ++it)
      {
        kv::Version v = std::stoi(it.key());

        // Make sure that the secret to store does not already exist
        auto search = secrets_map.find(v);
        if (search != secrets_map.end())
        {
          throw std::logic_error(fmt::format(
            "Cannot restore ledger secret that already exists: ", v));
        }

        // Unseal each sealed secret
        auto s = seal->unseal(it.value());
        if (!s.has_value())
        {
          throw std::logic_error(
            fmt::format("Ledger secret could not be unsealed: {}", v));
        }

        LOG_DEBUG_FMT(
          "Ledger secret successfully unsealed at version {}", it.key());

        auto new_secret = std::make_unique<LedgerSecret>(s.value());
        add_secret(v, std::move(new_secret), false);

        restored_versions.push_back(v);
      }

      return restored_versions;
    }

    // Called during recovery to promote temporary secret created at startup (v
    // = 1) to new current secret at the latest signed version
    bool promote_secret(kv::Version old_v, kv::Version new_v)
    {
      if (old_v == new_v)
      {
        return true;
      }

      auto search = secrets_map.find(new_v);
      if (search != secrets_map.end())
      {
        LOG_FAIL_FMT(
          "Cannot promote ledger secret {} - secret at this version already "
          "exists and would be overwritten",
          new_v);
        return false;
      }

      search = secrets_map.find(old_v);
      if (search == secrets_map.end())
      {
        LOG_FAIL_FMT(
          "Cannot promote ledger secret {} - secret does not exist from the "
          "version",
          old_v);
        return false;
      }

      secrets_map.emplace(new_v, std::move(search->second));
      secrets_map.erase(old_v);

      current_version = new_v;

      LOG_TRACE_FMT(
        "Ledger secret used at {} are now valid from {}", old_v, new_v);
      return true;
    }

    void seal_secret(kv::Version v)
    {
      if (!seal)
      {
        throw std::logic_error("No seal set to seal ledger secret");
      }

      auto search = secrets_map.find(v);
      if (search == secrets_map.end())
      {
        throw std::logic_error(
          fmt::format("Ledger secret to seal does not exist: {}", v));
      }

      if (!seal->seal(search->first, search->second->master))
      {
        throw std::logic_error(
          fmt::format("Ledger secret could not be sealed: {}", search->first));
      }
    }

    void seal_all()
    {
      for (auto const& s : secrets_map)
      {
        seal_secret(s.first);
      }
    }

    const LedgerSecret& get_current()
    {
      return *secrets_map.at(current_version).get();
    }

    std::optional<LedgerSecret> get_secret(kv::Version v)
    {
      auto search = secrets_map.find(v);
      if (search == secrets_map.end())
      {
        LOG_FAIL_FMT("Ledger secret at {} does not exist", v);
        return {};
      }

      return *search->second.get();
    }

    std::map<kv::Version, std::unique_ptr<LedgerSecret>>& get_secrets()
    {
      return secrets_map;
    }

    kv::Version get_current_version()
    {
      return current_version;
    }
  };
}
