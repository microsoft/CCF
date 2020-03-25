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

    LedgerSecret(bool random = false)
    {
      if (random)
      {
        master = tls::create_entropy()->random(MASTER_KEY_SIZE);
      }
    }

    LedgerSecret(const std::vector<uint8_t>& master_) : master(master_) {}
  };

  class LedgerSecrets
  {
  private:
    std::shared_ptr<AbstractSeal> seal;

    void add_secret(kv::Version v, LedgerSecret&& secret, bool force_seal)
    {
      if (seal && force_seal)
      {
        if (!seal->seal(v, secret.master))
        {
          throw std::logic_error(
            fmt::format("Ledger secret could not be sealed: {}", v));
        }
      }

      secrets_map.emplace(v, std::move(secret));
    }

  public:
    // Map of secrets that are valid from a specific version to the version of
    // the next entry in the map. The last entry in the map is valid for all
    // subsequent versions.
    std::map<kv::Version, LedgerSecret> secrets_map;

    LedgerSecrets() = default;

    // Called on startup to generate fresh ledger secret
    LedgerSecrets(std::shared_ptr<AbstractSeal> seal_, bool force_seal = true) :
      seal(seal_)
    {
      // Generate fresh ledger encryption key
      add_secret(1, LedgerSecret(true), force_seal);
    }

    // Called when a node joins the network and get given the ledger secrets
    // since the beginning of time
    LedgerSecrets(
      LedgerSecrets&& ledger_secrets_, std::shared_ptr<AbstractSeal> seal_) :
      secrets_map(std::move(ledger_secrets_.secrets_map)),
      seal(seal_)
    {}

    bool operator==(const LedgerSecrets& other) const
    {
      return secrets_map == other.secrets_map;
    }

    // Called when a backup is given past ledger secret via the store
    bool set_secret(kv::Version v, const std::vector<uint8_t>& raw_secret)
    {
      auto search = secrets_map.find(v);
      if (search != secrets_map.end())
      {
        return false;
      }

      add_secret(v, LedgerSecret(raw_secret), false);

      return true;
    }

    // Called when sealed secrets need to be stored during recovery
    std::vector<kv::Version> restore(const nlohmann::json& sealed_secrets)
    {
      std::vector<kv::Version> restored_versions;

      for (auto it = sealed_secrets.begin(); it != sealed_secrets.end(); ++it)
      {
        kv::Version v = std::stoi(it.key());

        auto search = secrets_map.find(v);
        if (search != secrets_map.end())
        {
          throw std::logic_error(fmt::format(
            "Cannot restore ledger secret that already exists: ", v));
        }

        auto s = seal->unseal(it.value());
        if (!s.has_value())
        {
          throw std::logic_error(
            fmt::format("Ledger secret could not be unsealed: {}", v));
        }

        LOG_DEBUG_FMT(
          "Ledger secret successfully unsealed at version {}", it.key());

        add_secret(v, LedgerSecret(s.value()), false);

        restored_versions.push_back(v);
      }

      return restored_versions;
    }

    std::vector<kv::Version> restore(LedgerSecrets&& ledger_secrets)
    {
      std::vector<kv::Version> restored_versions;

      for (auto it = ledger_secrets.secrets_map.begin();
           it != ledger_secrets.secrets_map.end();)
      {
        auto it_ = ledger_secrets.secrets_map.extract(it++);
        if (secrets_map.find(it_.key()) != secrets_map.end())
        {
          throw std::logic_error(fmt::format(
            "Ledger secret at version {} cannot be restored as they already "
            "exist",
            it_.key()));
        }
        restored_versions.emplace_back(it_.key());
        secrets_map.insert(std::move(it_));
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

      if (!seal->seal(search->first, search->second.master))
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

    std::optional<LedgerSecret> get_secret(kv::Version v)
    {
      auto search = secrets_map.find(v);
      if (search == secrets_map.end())
      {
        LOG_FAIL_FMT("Ledger secret at {} does not exist", v);
        return {};
      }

      return search->second;
    }
  };
}
