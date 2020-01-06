// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/kvtypes.h"
#include "secret.h"
#include "tls/keypair.h"

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

  // TODO: Rename this
  class NetworkSecrets
  {
    // Map of secrets that are valid from a specific version to the version of
    // the next entry in the map. The last entry in the map is valid for all
    // subsequent versions.
    std::map<kv::Version, std::unique_ptr<Secret>> secrets_map;

    std::unique_ptr<AbstractSeal> seal;
    kv::Version current_version = 0;

    void add_secret(
      kv::Version v, std::unique_ptr<Secret>&& secret, bool force_seal)
    {
      if (seal && force_seal)
      {
        if (!seal->seal(v, secret->ledger_master))
        {
          throw std::logic_error(
            "Ledger secret could not be sealed: " + std::to_string(v));
        }
      }

      // Add to secrets map
      secrets_map.emplace(v, std::move(secret));
      current_version = std::max(current_version, v);
    }

  public:
    // Called on startup to generate fresh network secrets
    NetworkSecrets(
      std::unique_ptr<AbstractSeal> seal_ = nullptr, bool force_seal = true) :
      seal(std::move(seal_))
    {
      // Generate fresh ledger encryption key
      // TODO: Should the random be moved to secret.h?
      auto new_secret =
        std::make_unique<Secret>(tls::create_entropy()->random(16));

      add_secret(0, std::move(new_secret), force_seal);
    }

    // Called when a node joins the network and get given the current network
    // secrets
    NetworkSecrets(
      kv::Version v,
      Secret& secret,
      std::unique_ptr<AbstractSeal> seal_ = nullptr,
      bool force_seal = true) :
      seal(std::move(seal_))
    {
      auto new_secret = std::make_unique<Secret>(secret);
      add_secret(v, std::move(new_secret), force_seal);
    }

    // Called when a backup is given past network secrets via the store
    bool set_secret(
      kv::Version v, const std::vector<uint8_t>& serialised_secret)
    {
      auto search = secrets_map.find(v);
      if (search != secrets_map.end())
      {
        LOG_FAIL_FMT("set_secret(): secrets already exist {}", v);
        return false;
      }

      auto new_secret = std::make_unique<Secret>(serialised_secret);
      add_secret(v, std::move(new_secret), false);

      return true;
    }

    // Called when sealed secrets need to be stored during recovery
    // TODO: This should not take a JSON object! :(
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
          throw std::logic_error(
            "Cannot restore secrets that already exist: " + std::to_string(v));
        }

        // Unseal each sealed data
        auto serialised_secrets = seal->unseal(it.value());
        if (!serialised_secrets.has_value())
        {
          throw std::logic_error(
            "Secrets could not be unsealed : " + std::to_string(v));
        }

        LOG_DEBUG_FMT("Secrets successfully unsealed at version {}", it.key());

        // Deserialise network secrets
        auto new_secret = std::make_unique<Secret>(serialised_secrets.value());
        add_secret(v, std::move(new_secret), false);

        restored_versions.push_back(v);
      }

      return restored_versions;
    }

    // Called during recovery to promote temporary secrets created at startup (v
    // = 0) to new current secrets at the latest signed version
    bool promote_secrets(kv::Version old_v, kv::Version new_v)
    {
      if (old_v == new_v)
      {
        return true;
      }

      auto search = secrets_map.find(new_v);
      if (search != secrets_map.end())
      {
        LOG_FAIL_FMT("promote_secrets(): secrets already exist");
        return false;
      }

      search = secrets_map.find(old_v);
      if (search == secrets_map.end())
      {
        LOG_FAIL_FMT("promote_secrets(): no secrets to promote");
        return false;
      }

      secrets_map.emplace(new_v, std::move(search->second));
      secrets_map.erase(old_v);

      current_version = new_v;

      LOG_DEBUG_FMT("Secrets used at {} are now valid from {}", old_v, new_v);
      return true;
    }

    bool seal_all()
    {
      if (!seal)
      {
        // TODO: Throw an exception?
        return false;
      }

      for (auto const& ns_ : secrets_map)
      {
        if (!seal->seal(ns_.first, ns_.second->ledger_master))
        {
          throw std::logic_error(
            "Network Secrets could not be sealed: " +
            std::to_string(ns_.first));
        }
      }

      return true;
    }

    const Secret& get_current()
    {
      return *secrets_map.at(current_version).get();
    }

    std::optional<std::vector<uint8_t>> get_serialised_secret(kv::Version v)
    {
      auto search = secrets_map.find(v);
      if (search == secrets_map.end())
      {
        LOG_FAIL_FMT("get_serialised_secret() {} does not exist", v);
        return {};
      }

      return search->second->ledger_master;
    }

    std::map<kv::Version, std::unique_ptr<Secret>>& get_secrets()
    {
      return secrets_map;
    }

    kv::Version get_current_version()
    {
      return current_version;
    }
  };
}
