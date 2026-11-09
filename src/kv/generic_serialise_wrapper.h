// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/kv/serialisers/serialised_entry.h"
#include "ds/ccf_assert.h"
#include "ds/serialized.h"
#include "kv/claims.h"
#include "kv_types.h"
#include "serialised_entry_format.h"

#include <algorithm>
#include <optional>
#include <span>

namespace ccf::kv
{
  template <typename W>
  class GenericSerialiseWrapper : public KvStoreSerialiser
  {
  private:
    W public_writer;
    W private_writer;
    W* current_writer;
    TxID tx_id;
    EntryType entry_type;
    SerialisedEntryFlags header_flags;
    size_t max_transaction_size;

    std::shared_ptr<AbstractTxEncryptor> crypto_util;

    // must only be set by set_current_domain, since it affects current_writer
    SecurityDomain current_domain{SecurityDomain::PUBLIC};

    // If true, consider historical ledger secrets when encrypting entries
    bool historical_hint;

    // Set by finalise_in_place(), which encrypts the private domain in place
    // with an IV determined by tx_id: encrypting it again, by either
    // finalise_in_place() or get_raw_data(), would restore the plaintext
    bool finalised = false;

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
        {
          current_writer = &private_writer;
          current_domain = SecurityDomain::PRIVATE;
          break;
        }
        case SecurityDomain::PUBLIC:
        {
          current_writer = &public_writer;
          current_domain = SecurityDomain::PUBLIC;
          break;
        }
        case SecurityDomain::SECURITY_DOMAIN_MAX:
        {
          throw std::logic_error("Invalid security domain");
        }
      }
    }

    // Size of an entry with domains of the given sizes. Without an encryptor
    // (unit tests only), the private domain is not serialised.
    [[nodiscard]] size_t serialised_entry_size(
      size_t public_size, size_t private_size) const
    {
      return public_domain_offset(crypto_util) + public_size +
        (crypto_util ? private_size : 0);
    }

    // Completes an entry, of serialised_entry_size(public_size,
    // private_domain.size()), whose public domain is already in place: writes
    // the headers which precede it, and encrypts private_domain into the rest
    // of the entry, which may be private_domain itself.
    void write_headers_and_encrypt(
      std::span<uint8_t> entry,
      size_t public_size,
      std::span<const uint8_t> private_domain)
    {
      SerialisedEntryHeader entry_header;
      entry_header.version = entry_format_v1;
      entry_header.flags = header_flags;
      entry_header.set_size(entry.size() - sizeof(SerialisedEntryHeader));

      auto* data_ = entry.data();
      auto size_ = entry.size();
      serialized::write(data_, size_, entry_header);

      if (!crypto_util)
      {
        return;
      }

      const auto header_size = crypto_util->get_header_length();
      std::span<uint8_t> serialised_hdr(data_, header_size);
      data_ += header_size;
      size_ -= header_size;
      serialized::write(data_, size_, public_size);

      if (!crypto_util->encrypt(
            private_domain,
            std::span<const uint8_t>(data_, public_size),
            serialised_hdr,
            std::span<uint8_t>(data_ + public_size, private_domain.size()),
            tx_id,
            entry_type,
            historical_hint))
      {
        throw KvSerialiserException(fmt::format(
          "Could not serialise transaction at seqno {}", tx_id.seqno));
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
      bool historical_hint_ = false,
      size_t max_transaction_size_ = max_serialised_entry_size) :
      GenericSerialiseWrapper(
        W{},
        W{},
        std::move(e),
        tx_id_,
        entry_type_,
        header_flags_,
        commit_evidence_digest_,
        claims_digest_,
        historical_hint_,
        max_transaction_size_)
    {}

    // As above, serialising each domain with the given writer, e.g. a
    // SpanWriter over that domain's region of the output entry (see
    // public_domain_offset() and finalise_in_place())
    GenericSerialiseWrapper(
      W&& public_writer_,
      W&& private_writer_,
      std::shared_ptr<AbstractTxEncryptor> e,
      const TxID& tx_id_,
      EntryType entry_type_,
      SerialisedEntryFlags header_flags_,
      const ccf::crypto::Sha256Hash& commit_evidence_digest_ = {},
      const ccf::ClaimsDigest& claims_digest_ = ccf::no_claims(),
      bool historical_hint_ = false,
      size_t max_transaction_size_ = max_serialised_entry_size) :
      public_writer(std::move(public_writer_)),
      private_writer(std::move(private_writer_)),
      tx_id(tx_id_),
      entry_type(entry_type_),
      header_flags(header_flags_),
      max_transaction_size(max_transaction_size_),
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

    void start_map(const std::string& name, SecurityDomain domain) override
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

    void serialise_raw(const std::vector<uint8_t>& raw) override
    {
      serialise_internal(raw);
    }

    void serialise_raw_in_place(
      size_t size, const std::function<void(std::span<uint8_t>)>& fill) override
    {
      current_writer->append_size_prefixed_in_place(size, fill);
    }

    void serialise_view_history(
      const std::vector<Version>& view_history) override
    {
      serialise_internal(view_history);
    }

    void serialise_entry_version(const Version& version) override
    {
      serialise_internal(version);
    }

    void serialise_count_header(uint64_t ctr) override
    {
      serialise_internal(ctr);
    }

    void serialise_write(
      const SerialisedKey& k, const SerialisedValue& v) override
    {
      serialise_internal(k);
      serialise_internal(v);
    }

    void serialise_remove(const SerialisedKey& k) override
    {
      serialise_internal(k);
    }

    std::vector<uint8_t> get_raw_data() override
    {
      if (finalised)
      {
        throw std::logic_error("Entry was already finalised in place");
      }

      // make sure the private buffer is empty when we return
      auto writer_guard_func = [](W* writer) { writer->clear(); };
      std::unique_ptr<decltype(private_writer), decltype(writer_guard_func)>
        writer_guard(&private_writer, writer_guard_func);

      // Serialise directly from the writers' buffers, which may be as large as
      // a snapshot, rather than from copies of them
      return serialise_domains(public_writer.view(), private_writer.view());
    }

    [[nodiscard]] size_t get_public_domain_size() const
    {
      return public_writer.size();
    }

    [[nodiscard]] size_t get_private_domain_size() const
    {
      return private_writer.size();
    }

    /** Offset of the public domain in a serialised entry. The private domain
     * immediately follows the public domain.
     */
    static size_t public_domain_offset(
      const std::shared_ptr<AbstractTxEncryptor>& e)
    {
      return sizeof(SerialisedEntryHeader) +
        (e ? e->get_header_length() + sizeof(size_t) : 0);
    }

    /** Completes an entry whose domains were serialised in place, by writers
     * over its public and private regions: writes the headers and encrypts the
     * private domain in place. entry must be exactly the size of the
     * serialised entry. May be called at most once, even if it throws.
     */
    void finalise_in_place(std::span<uint8_t> entry)
    {
      if (finalised)
      {
        throw std::logic_error("Entry was already finalised in place");
      }
      finalised = true;

      const auto public_size = public_writer.size();
      const auto private_size = private_writer.size();
      if (!crypto_util && private_size != 0)
      {
        throw std::logic_error(
          "Private domain cannot be serialised without an encryptor");
      }

      const auto entry_size = serialised_entry_size(public_size, private_size);
      if (entry.size() != entry_size)
      {
        throw std::logic_error(fmt::format(
          "Entry of size {} does not match serialised size {}",
          entry.size(),
          entry_size));
      }

      const auto public_domain =
        entry.subspan(public_domain_offset(crypto_util), public_size);
      const auto private_domain = entry.last(private_size);
      if (
        (public_size != 0 &&
         public_writer.view().data() != public_domain.data()) ||
        (private_size != 0 &&
         private_writer.view().data() != private_domain.data()))
      {
        throw std::logic_error("Domains were not serialised in place");
      }

      if (entry_size > max_transaction_size)
      {
        throw KvSerialiserException(describe_serialised_entry_size_error(
          entry_size, max_transaction_size));
      }

      write_headers_and_encrypt(entry, public_size, private_domain);
    }

    /** Size of the ledger entry which get_raw_data() would produce for
     * everything serialised so far.
     *
     * This covers the whole entry: the fixed-size ledger entry header, the
     * ledger encryption header, the public domain size field, and both
     * domains. Encryption does not change the size of the private domain, so
     * this is exact.
     */
    [[nodiscard]] size_t get_serialised_size() const
    {
      return serialised_entry_size(public_writer.size(), private_writer.size());
    }

    std::vector<uint8_t> serialise_domains(
      const std::vector<uint8_t>& serialised_public_domain,
      const std::vector<uint8_t>& serialised_private_domain) override
    {
      return serialise_domains(
        std::span<const uint8_t>(serialised_public_domain),
        std::span<const uint8_t>(serialised_private_domain));
    }

    std::vector<uint8_t> serialise_domains(
      std::span<const uint8_t> serialised_public_domain,
      std::span<const uint8_t> serialised_private_domain)
    {
      // If no crypto util is set (unit test only), only the header and public
      // domain are serialised
      const size_t entry_size = serialised_entry_size(
        serialised_public_domain.size(), serialised_private_domain.size());

      // The configured limit applies to the whole serialised ledger entry,
      // including the fixed-size entry header.
      if (entry_size > max_transaction_size)
      {
        // Non-reserved transactions measure this exact size before applying
        // their changes. Reserved signature transactions use the largest
        // representable entry size here. Reaching this point is always fatal.
        throw KvSerialiserException(describe_serialised_entry_size_error(
          entry_size, max_transaction_size));
      }

      CCF_ASSERT_FMT(
        crypto_util || serialised_private_domain.empty(),
        "Serialised does not have a crypto util but some private data were "
        "serialised");

      std::vector<uint8_t> entry(entry_size);
      const auto public_domain = std::span<uint8_t>(entry).subspan(
        public_domain_offset(crypto_util), serialised_public_domain.size());
      std::ranges::copy(serialised_public_domain, public_domain.begin());
      write_headers_and_encrypt(
        entry, serialised_public_domain.size(), serialised_private_domain);

      return entry;
    }
  };

  template <typename R>
  class GenericDeserialiseWrapper : public KvStoreDeserialiser
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

    ccf::ClaimsDigest&& consume_claims_digest() override
    {
      return std::move(claims_digest);
    }

    std::optional<ccf::crypto::Sha256Hash>&& consume_commit_evidence_digest()
      override
    {
      return std::move(commit_evidence_digest);
    }

    std::optional<Version> init(
      const uint8_t* data,
      size_t size,
      ccf::kv::Term& term,
      EntryFlags& flags,
      bool historical_hint) override
    {
      return init_internal(data, size, term, flags, historical_hint, nullptr);
    }

    /** As init(), but decrypts the private domain in place, overwriting the
     * ciphertext in data, rather than into a separate buffer. data must
     * outlive this deserialiser, and is unspecified if this fails.
     */
    std::optional<Version> init_in_place(
      uint8_t* data,
      size_t size,
      ccf::kv::Term& term,
      EntryFlags& flags,
      bool historical_hint)
    {
      return init_internal(data, size, term, flags, historical_hint, data);
    }

  private:
    // mutable_data is either nullptr or data, writable
    std::optional<Version> init_internal(
      const uint8_t* data,
      size_t size,
      ccf::kv::Term& term,
      EntryFlags& flags,
      bool historical_hint,
      uint8_t* mutable_data)
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
        public_reader.init(std::span<const uint8_t>(data_, size_));
        read_public_header();
        return version;
      }

      serialized::skip(data_, size_, crypto_util->get_header_length());
      const auto public_domain_length = serialized::read<size_t>(data_, size_);
      if (public_domain_length > size_)
      {
        throw std::logic_error(fmt::format(
          "Public domain length {} exceeds remaining entry size {}",
          public_domain_length,
          size_));
      }

      const auto* data_public = data_;
      public_reader.init(
        std::span<const uint8_t>(data_public, public_domain_length));
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

      const auto aad =
        std::span<const uint8_t>(data_public, public_domain_length);
      const auto gcm_hdr = std::span<const uint8_t>(
        gcm_hdr_data, crypto_util->get_header_length());

      if (mutable_data != nullptr)
      {
        const auto private_domain =
          std::span<uint8_t>(mutable_data + (data_ - data), size_);
        if (!crypto_util->decrypt_in_place(
              private_domain, aad, gcm_hdr, version, term, historical_hint))
        {
          return std::nullopt;
        }
        private_reader.init(private_domain);
        return version;
      }

      if (!crypto_util->decrypt(
            std::span<const uint8_t>(data_, size_),
            aad,
            gcm_hdr,
            decrypted_buffer,
            version,
            term,
            historical_hint))
      {
        return std::nullopt;
      }

      private_reader.init(decrypted_buffer);
      return version;
    }

  public:
    std::optional<std::string> start_map() override
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

    Version deserialise_entry_version() override
    {
      return current_reader->template read_next<Version>();
    }

    uint64_t deserialise_read_header() override
    {
      return current_reader->template read_next<uint64_t>();
    }

    std::tuple<SerialisedKey, Version> deserialise_read() override
    {
      return {
        current_reader->template read_next<SerialisedKey>(),
        current_reader->template read_next<Version>()};
    }

    uint64_t deserialise_write_header() override
    {
      return current_reader->template read_next<uint64_t>();
    }

    std::tuple<SerialisedKey, SerialisedValue> deserialise_write() override
    {
      return {
        current_reader->template read_next<SerialisedKey>(),
        current_reader->template read_next<SerialisedValue>()};
    }

    std::vector<uint8_t> deserialise_raw() override
    {
      return current_reader->template read_next<std::vector<uint8_t>>();
    }

    std::span<const uint8_t> deserialise_raw_span() override
    {
      return current_reader->read_next_span();
    }

    std::vector<Version> deserialise_view_history() override
    {
      return current_reader->template read_next<std::vector<Version>>();
    }

    uint64_t deserialise_remove_header() override
    {
      return current_reader->template read_next<uint64_t>();
    }

    SerialisedKey deserialise_remove() override
    {
      return current_reader->template read_next<SerialisedKey>();
    }

    bool end() override
    {
      return current_reader->is_eos() && public_reader.is_eos();
    }
  };
}
