// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "kv_types.h"
#include "serialised_entry.h"

#include <optional>

namespace kv
{
  using SerialisedKey = kv::serialisers::SerialisedEntry;
  using SerialisedValue = kv::serialisers::SerialisedEntry;

  enum class KvOperationType : uint32_t
  {
    KOT_NOT_SUPPORTED = 0,
    KOT_SET_VERSION = (1 << 0),
    KOT_MAP_START_INDICATOR = (1 << 1),
    KOT_ENTRY_VERSION = (1 << 2),
    KOT_READ = (1 << 3),
    KOT_WRITE_VERSION = (1 << 4),
    KOT_WRITE = (1 << 5),
    KOT_REMOVE_VERSION = (1 << 6),
    KOT_REMOVE = (1 << 7),
  };

  typedef std::underlying_type<KvOperationType>::type KotBase;

  inline KvOperationType operator&(
    const KvOperationType& a, const KvOperationType& b)
  {
    return static_cast<KvOperationType>(
      static_cast<KotBase>(a) & static_cast<KotBase>(b));
  }

  inline KvOperationType operator|(
    const KvOperationType& a, const KvOperationType& b)
  {
    return static_cast<KvOperationType>(
      static_cast<KotBase>(a) | static_cast<KotBase>(b));
  }

  template <typename W>
  class GenericSerialiseWrapper
  {
  private:
    W public_writer;
    W private_writer;
    W* current_writer;
    TxID tx_id;
    Version max_conflict_version;
    bool is_snapshot;

    std::shared_ptr<AbstractTxEncryptor> crypto_util;

    // must only be set by set_current_domain, since it affects current_writer
    SecurityDomain current_domain;

    template <typename T>
    void serialise_internal(T&& t)
    {
      current_writer->append(std::forward<T>(t));
    }

    template <typename T>
    void serialise_internal_pre_serialised(const T& raw)
    {
      current_writer->template append_pre_serialised<T>(raw);
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
      const Version& max_conflict_version_,
      bool is_snapshot_ = false) :
      tx_id(tx_id_),
      max_conflict_version(max_conflict_version_),
      is_snapshot(is_snapshot_),
      crypto_util(e)
    {
      set_current_domain(SecurityDomain::PUBLIC);
      serialise_internal(is_snapshot);
      serialise_internal(tx_id.version);
      serialise_internal(max_conflict_version);
    }

    void start_map(const std::string& name, SecurityDomain domain)
    {
      if (domain == SecurityDomain::PRIVATE && !crypto_util)
      {
        throw KvSerialiserException(fmt::format(
          "Private map {} cannot be serialised without an encryptor", name));
      }

      if (domain != current_domain)
        set_current_domain(domain);

      serialise_internal(KvOperationType::KOT_MAP_START_INDICATOR);
      serialise_internal(name);
    }

    void serialise_raw(const std::vector<uint8_t>& raw)
    {
      serialise_internal_pre_serialised(raw);
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
      serialise_internal_pre_serialised(k);
      serialise_internal(version);
    }

    void serialise_write(const SerialisedKey& k, const SerialisedValue& v)
    {
      serialise_internal_pre_serialised(k);
      serialise_internal_pre_serialised(v);
    }

    void serialise_write_version(
      const SerialisedKey& k, const SerialisedValue& v, const Version& version)
    {
      serialise_internal(KvOperationType::KOT_WRITE_VERSION);
      serialise_internal_pre_serialised(k);
      serialise_internal_pre_serialised(v);
      serialise_internal(version);
    }

    void serialise_remove_version(const SerialisedKey& k)
    {
      serialise_internal(KvOperationType::KOT_REMOVE_VERSION);
      serialise_internal_pre_serialised(k);
    }

    void serialise_remove(const SerialisedKey& k)
    {
      serialise_internal_pre_serialised(k);
    }

    std::vector<uint8_t> get_raw_data()
    {
      // make sure the private buffer is empty when we return
      auto writer_guard_func = [](W* writer) { writer->clear(); };
      std::unique_ptr<decltype(private_writer), decltype(writer_guard_func)>
        writer_guard(&private_writer, writer_guard_func);

      auto serialised_public_domain = public_writer.get_raw_data();

      // If no crypto util is set, all maps have been serialised by the public
      // writer.
      if (!crypto_util)
      {
        return serialised_public_domain;
      }

      auto serialised_private_domain = private_writer.get_raw_data();

      return serialise_domains(
        serialised_public_domain, serialised_private_domain);
    }

    std::vector<uint8_t> serialise_domains(
      const std::vector<uint8_t>& serialised_public_domain,
      const std::vector<uint8_t>& serialised_private_domain =
        std::vector<uint8_t>())
    {
      std::vector<uint8_t> serialised_tx;
      std::vector<uint8_t> serialised_hdr;
      std::vector<uint8_t> encrypted_private_domain(
        serialised_private_domain.size());

      crypto_util->encrypt(
        serialised_private_domain,
        serialised_public_domain,
        serialised_hdr,
        encrypted_private_domain,
        tx_id,
        is_snapshot);

      // Serialise entire tx
      // Format: gcm hdr (iv + tag) + len of public domain + public domain +
      // encrypted privated domain
      auto space = serialised_hdr.size() + sizeof(size_t) +
        serialised_public_domain.size() + encrypted_private_domain.size();
      serialised_tx.resize(space);
      auto data_ = serialised_tx.data();

      serialized::write(
        data_, space, serialised_hdr.data(), serialised_hdr.size());
      serialized::write(data_, space, serialised_public_domain.size());
      serialized::write(
        data_,
        space,
        serialised_public_domain.data(),
        serialised_public_domain.size());
      if (encrypted_private_domain.size() > 0)
      {
        serialized::write(
          data_,
          space,
          encrypted_private_domain.data(),
          encrypted_private_domain.size());
      }

      return serialised_tx;
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
    KvOperationType unhandled_op;
    bool is_snapshot;
    Version version;
    Version max_conflict_version;
    std::shared_ptr<AbstractTxEncryptor> crypto_util;
    std::optional<SecurityDomain> domain_restriction;

    bool try_read_op(KvOperationType type)
    {
      return try_read_op(type, *current_reader);
    }

    bool try_read_op(KvOperationType type, R& reader)
    {
      return try_read_op_flag(type, reader) == type;
    }

    KvOperationType try_read_op_flag(KvOperationType type)
    {
      return try_read_op_flag(type, *current_reader);
    }

    KvOperationType try_read_op_flag(KvOperationType type, R& reader)
    {
      if (unhandled_op != KvOperationType::KOT_NOT_SUPPORTED)
      {
        auto curr_type = (type & unhandled_op);
        if (curr_type != KvOperationType::KOT_NOT_SUPPORTED)
        {
          // clear cached op header
          unhandled_op = KvOperationType::KOT_NOT_SUPPORTED;
        }
        return curr_type;
      }

      auto next_op = reader.template read_next<KvOperationType>();
      if ((type & next_op) == next_op)
      {
        return next_op;
      }

      unhandled_op = next_op;
      return KvOperationType::KOT_NOT_SUPPORTED;
    }

    // Should only be called once, once the GCM header and length of public
    // domain have been read
    void read_public_header()
    {
      is_snapshot = public_reader.template read_next<bool>();
      version = public_reader.template read_next<Version>();
      max_conflict_version = public_reader.template read_next<Version>();
    }

  public:
    GenericDeserialiseWrapper(
      std::shared_ptr<AbstractTxEncryptor> e,
      std::optional<SecurityDomain> domain_restriction = std::nullopt) :
      unhandled_op(KvOperationType::KOT_NOT_SUPPORTED),
      crypto_util(e),
      domain_restriction(domain_restriction)
    {}

    std::optional<std::tuple<Version, Version>> init(
      const uint8_t* data, size_t size, bool is_historical = false)
    {
      current_reader = &public_reader;
      auto data_ = data;
      auto size_ = size;

      // If the kv store has no encryptor, assume that the serialised tx is
      // public only with no header
      if (!crypto_util)
      {
        public_reader.init(data, size);
        read_public_header();
        return std::make_tuple(version, max_conflict_version);
      }

      // Skip gcm hdr and read length of public domain
      serialized::skip(data_, size_, crypto_util->get_header_length());
      auto public_domain_length = serialized::read<size_t>(data_, size_);

      // Set public reader
      auto data_public = data_;
      public_reader.init(data_public, public_domain_length);

      read_public_header();

      // If the domain is public only, skip the decryption and only return the
      // public data
      if (
        domain_restriction.has_value() &&
        domain_restriction.value() == SecurityDomain::PUBLIC)
      {
        return std::make_tuple(version, max_conflict_version);
      }

      // Go to start of private domain
      serialized::skip(data_, size_, public_domain_length);
      decrypted_buffer.resize(size_);

      if (!crypto_util->decrypt(
            {data_, data_ + size_},
            {data_public, data_public + public_domain_length},
            {data, data + crypto_util->get_header_length()},
            decrypted_buffer,
            version,
            is_historical))
      {
        return std::nullopt;
      }

      // Set private reader
      private_reader.init(decrypted_buffer.data(), decrypted_buffer.size());
      return std::make_tuple(version, max_conflict_version);
    }

    std::optional<std::string> start_map()
    {
      if (current_reader->is_eos())
      {
        if (current_reader == &public_reader && !private_reader.is_eos())
          current_reader = &private_reader;
        else
          return {};
      }

      if (!try_read_op(KvOperationType::KOT_MAP_START_INDICATOR))
      {
        return {};
      }

      return std::optional<std::string>{
        current_reader->template read_next<std::string>()};
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
        current_reader->template read_next_pre_serialised<SerialisedKey>(),
        current_reader->template read_next<Version>()};
    }

    uint64_t deserialise_write_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    std::tuple<SerialisedKey, SerialisedValue> deserialise_write()
    {
      return {
        current_reader->template read_next_pre_serialised<SerialisedKey>(),
        current_reader->template read_next_pre_serialised<SerialisedValue>()};
    }

    std::vector<uint8_t> deserialise_raw()
    {
      return current_reader
        ->template read_next_pre_serialised<std::vector<uint8_t>>();
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
      return current_reader->template read_next_pre_serialised<SerialisedKey>();
    }

    bool end()
    {
      return current_reader->is_eos() && public_reader.is_eos();
    }
  };
}
