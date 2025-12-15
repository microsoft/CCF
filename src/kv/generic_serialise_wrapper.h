// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/serialisers/serialised_entry.h"
#include "ds/ccf_assert.h"
#include "kv_types.h"
#include "node/rpc/claims.h"
#include "serialised_entry_format.h"

#include <optional>

namespace ccf::kv
{
  using SerialisedKey = ccf::kv::serialisers::SerialisedEntry;
  using SerialisedValue = ccf::kv::serialisers::SerialisedEntry;

  template <typename W>
  class GenericSerialiseWrapper
  {
  private:
    W public_writer;
    W private_writer;
    W* current_writer;
    TxID tx_id;
    EntryType entry_type;
    SerialisedEntryFlags header_flags;

    std::shared_ptr<AbstractTxEncryptor> crypto_util;

    // must only be set by set_current_domain, since it affects current_writer
    SecurityDomain current_domain{SecurityDomain::PUBLIC};

    // If true, consider historical ledger secrets when encrypting entries
    bool historical_hint;

    template <typename T>
    void serialise_internal(const T& t)
    {
      current_writer->append(t);
    }

    void set_current_domain(SecurityDomain domain)
    {
      switch (domain)
      {
        case SecurityDomain::PRIVATE:
          current_writer = &private_writer;
          current_domain = SecurityDomain::PRIVATE;
          break;
        case SecurityDomain::PUBLIC:
          current_writer = &public_writer;
          current_domain = SecurityDomain::PUBLIC;
          break;
        default:
          break;
      }
    }

  public:
    GenericSerialiseWrapper(
      std::shared_ptr<AbstractTxEncryptor> e,
      const TxID& tx_id_,
      EntryType entry_type_,
      SerialisedEntryFlags header_flags_,
      // The evidence and claims digest must be systematically present
      // in regular transactions, but absent in snapshots.
      const ccf::crypto::Sha256Hash& commit_evidence_digest_ = {},
      const ccf::ClaimsDigest& claims_digest_ = ccf::no_claims(),
      bool historical_hint_ = false) :
      tx_id(tx_id_),
      entry_type(entry_type_),
      header_flags(header_flags_),
      crypto_util(std::move(e)),
      historical_hint(historical_hint_)
    {
      set_current_domain(SecurityDomain::PUBLIC);
      serialise_internal(entry_type);
      serialise_internal(tx_id.seqno);
      if (has_claims(entry_type))
      {
        serialise_internal(claims_digest_.value());
      }
      if (has_commit_evidence(entry_type))
      {
        serialise_internal(commit_evidence_digest_);
      }
      // Write a placeholder max_conflict_version for compatibility
      serialise_internal((Version)0u);
    }

    void start_map(const std::string& name, SecurityDomain domain)
    {
      if (domain == SecurityDomain::PRIVATE && !crypto_util)
      {
        throw KvSerialiserException(fmt::format(
          "Private map {} cannot be serialised without an encryptor", name));
      }

      if (domain != current_domain)
      {
        set_current_domain(domain);
      }

      serialise_internal(name);
    }

    void serialise_raw(const std::vector<uint8_t>& raw)
    {
      serialise_internal(raw);
    }

    void serialise_view_history(const std::vector<Version>& view_history)
    {
      serialise_internal(view_history);
    }

    template <class Version>
    void serialise_entry_version(const Version& version)
    {
      serialise_internal(version);
    }

    void serialise_count_header(uint64_t ctr)
    {
      serialise_internal(ctr);
    }

    void serialise_read(const SerialisedKey& k, const Version& version)
    {
      serialise_internal(k);
      serialise_internal(version);
    }

    void serialise_write(const SerialisedKey& k, const SerialisedValue& v)
    {
      serialise_internal(k);
      serialise_internal(v);
    }

    void serialise_remove(const SerialisedKey& k)
    {
      serialise_internal(k);
    }

    std::vector<uint8_t> get_raw_data()
    {
      // make sure the private buffer is empty when we return
      auto writer_guard_func = [](W* writer) { writer->clear(); };
      std::unique_ptr<decltype(private_writer), decltype(writer_guard_func)>
        writer_guard(&private_writer, writer_guard_func);

      return serialise_domains(
        public_writer.get_raw_data(), private_writer.get_raw_data());
    }

    std::vector<uint8_t> serialise_domains(
      const std::vector<uint8_t>& serialised_public_domain,
      const std::vector<uint8_t>& serialised_private_domain =
        std::vector<uint8_t>())
    {
      size_t size_ = serialised_public_domain.size();

      SerialisedEntryHeader entry_header;
      entry_header.version = entry_format_v1;
      entry_header.flags = header_flags;

      // If no crypto util is set (unit test only), only the header and public
      // domain are serialised
      if (crypto_util)
      {
        size_ += crypto_util->get_header_length() + sizeof(size_t) +
          serialised_private_domain.size();
      }
      entry_header.set_size(size_);

      size_ += sizeof(SerialisedEntryHeader);

      std::vector<uint8_t> entry(size_);
      auto* data_ = entry.data();

      serialized::write(data_, size_, entry_header);

      if (!crypto_util)
      {
        CCF_ASSERT_FMT(
          serialised_private_domain.empty(),
          "Serialised does not have a crypto util but some private data were "
          "serialised");
        serialized::write(
          data_,
          size_,
          serialised_public_domain.data(),
          serialised_public_domain.size());

        return entry;
      }

      std::vector<uint8_t> serialised_hdr;
      std::vector<uint8_t> encrypted_private_domain(
        serialised_private_domain.size());

      if (!crypto_util->encrypt(
            serialised_private_domain,
            serialised_public_domain,
            serialised_hdr,
            encrypted_private_domain,
            tx_id,
            entry_type,
            historical_hint))
      {
        throw KvSerialiserException(fmt::format(
          "Could not serialise transaction at seqno {}", tx_id.seqno));
      }

      serialized::write(
        data_, size_, serialised_hdr.data(), serialised_hdr.size());
      serialized::write(data_, size_, serialised_public_domain.size());
      serialized::write(
        data_,
        size_,
        serialised_public_domain.data(),
        serialised_public_domain.size());
      if (!encrypted_private_domain.empty())
      {
        serialized::write(
          data_,
          size_,
          encrypted_private_domain.data(),
          encrypted_private_domain.size());
      }

      return entry;
    }
  };

  template <typename R>
  class GenericDeserialiseWrapper
  {
  private:
    R public_reader;
    R private_reader;
    R* current_reader;
    std::vector<uint8_t> decrypted_buffer;
    EntryType entry_type{EntryType::WriteSet};
    // Present systematically in regular transactions, but absent from snapshots
    ccf::ClaimsDigest claims_digest = ccf::no_claims();
    // Present systematically in regular transactions, but absent from snapshots
    std::optional<ccf::crypto::Sha256Hash> commit_evidence_digest =
      std::nullopt;
    Version version{0};
    std::shared_ptr<AbstractTxEncryptor> crypto_util;
    std::optional<SecurityDomain> domain_restriction;

    // Should only be called once, once the GCM header and length of public
    // domain have been read
    void read_public_header()
    {
      entry_type = public_reader.template read_next<EntryType>();
      version = public_reader.template read_next<Version>();
      if (has_claims(entry_type))
      {
        auto digest_array =
          public_reader
            .template read_next<ccf::ClaimsDigest::Digest::Representation>();
        claims_digest.set(std::move(digest_array));
      }
      if (has_commit_evidence(entry_type))
      {
        auto digest_array =
          public_reader
            .template read_next<ccf::crypto::Sha256Hash::Representation>();
        commit_evidence_digest =
          ccf::crypto::Sha256Hash::from_representation(digest_array);
      }
      // max_conflict_version is included for compatibility, but currently
      // ignored
      const auto _ = public_reader.template read_next<Version>();
    }

  public:
    GenericDeserialiseWrapper(
      std::shared_ptr<AbstractTxEncryptor> e,
      std::optional<SecurityDomain> domain_restriction = std::nullopt) :
      crypto_util(std::move(e)),
      domain_restriction(domain_restriction)
    {}

    ccf::ClaimsDigest&& consume_claims_digest()
    {
      return std::move(claims_digest);
    }

    std::optional<ccf::crypto::Sha256Hash>&& consume_commit_evidence_digest()
    {
      return std::move(commit_evidence_digest);
    }

    std::optional<Version> init(
      const uint8_t* data,
      size_t size,
      ccf::kv::Term& term,
      EntryFlags& flags,
      bool historical_hint = false)
    {
      current_reader = &public_reader;
      const auto* data_ = data;
      auto size_ = size;

      const auto tx_header =
        serialized::read<SerialisedEntryHeader>(data_, size_);

      flags = static_cast<EntryFlags>(tx_header.flags);

      if (tx_header.size != size_)
      {
        throw std::logic_error(fmt::format(
          "Reported size in entry header {} does not match size of entry {}",
          tx_header.size,
          size_));
      }

      const auto* gcm_hdr_data = data_;

      switch (tx_header.version)
      {
        case entry_format_v1:
        {
          // Proceed with deserialisation
          break;
        }
        default:
        {
          throw std::logic_error(fmt::format(
            "Cannot deserialise entry format {}", tx_header.version));
        }
      }

      // If the kv store has no encryptor, assume that the serialised tx is
      // public only with no header (test only)
      if (!crypto_util)
      {
        public_reader.init(data_, size_);
        read_public_header();
        return version;
      }

      serialized::skip(data_, size_, crypto_util->get_header_length());
      auto public_domain_length = serialized::read<size_t>(data_, size_);

      const auto* data_public = data_;
      public_reader.init(data_public, public_domain_length);
      read_public_header();

      // If the domain is public only, skip the decryption and only return the
      // public data (integrity will be verified at the next signature entry)
      if (
        domain_restriction.has_value() &&
        domain_restriction.value() == SecurityDomain::PUBLIC)
      {
        // Retrieve term from GCM header, even if the domain restriction is set
        // to public and the decryption is skipped, so that the term for the
        // deserialised entry can be reported
        term =
          crypto_util->get_term(gcm_hdr_data, crypto_util->get_header_length());

        return version;
      }

      serialized::skip(data_, size_, public_domain_length);
      decrypted_buffer.resize(size_);

      if (!crypto_util->decrypt(
            {data_, data_ + size_},
            {data_public, data_public + public_domain_length},
            {gcm_hdr_data, gcm_hdr_data + crypto_util->get_header_length()},
            decrypted_buffer,
            version,
            term,
            historical_hint))
      {
        return std::nullopt;
      }

      private_reader.init(decrypted_buffer.data(), decrypted_buffer.size());
      return version;
    }

    std::optional<std::string> start_map()
    {
      if (current_reader->is_eos())
      {
        if (current_reader == &public_reader && !private_reader.is_eos())
        {
          current_reader = &private_reader;
        }
        else
        {
          return std::nullopt;
        }
      }

      return current_reader->template read_next<std::string>();
    }

    Version deserialise_entry_version()
    {
      return current_reader->template read_next<Version>();
    }

    uint64_t deserialise_read_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    std::tuple<SerialisedKey, Version> deserialise_read()
    {
      return {
        current_reader->template read_next<SerialisedKey>(),
        current_reader->template read_next<Version>()};
    }

    uint64_t deserialise_write_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    std::tuple<SerialisedKey, SerialisedValue> deserialise_write()
    {
      return {
        current_reader->template read_next<SerialisedKey>(),
        current_reader->template read_next<SerialisedValue>()};
    }

    std::vector<uint8_t> deserialise_raw()
    {
      return current_reader->template read_next<std::vector<uint8_t>>();
    }

    std::vector<Version> deserialise_view_history()
    {
      return current_reader->template read_next<std::vector<Version>>();
    }

    uint64_t deserialise_remove_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    SerialisedKey deserialise_remove()
    {
      return current_reader->template read_next<SerialisedKey>();
    }

    bool end()
    {
      return current_reader->is_eos() && public_reader.is_eos();
    }
  };
}
