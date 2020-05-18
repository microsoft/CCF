// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "kv_types.h"

#include <optional>

namespace kv
{
  enum class KvOperationType : uint32_t
  {
    KOT_NOT_SUPPORTED = 0,
    KOT_SET_VERSION = (1 << 0),
    KOT_MAP_START_INDICATOR = (1 << 1),
    KOT_READ_VERSION = (1 << 2),
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

  template <typename K, typename V, typename Version>
  struct KeyValVersion
  {
    K key;
    V value;
    Version version;
    bool is_remove;

    KeyValVersion(K k, V v, Version ver, bool is_rem) :
      key(k),
      value(v),
      version(ver),
      is_remove(is_rem)
    {}
  };

  template <typename W>
  class GenericSerialiseWrapper
  {
  private:
    W public_writer;
    W private_writer;
    W* current_writer;
    Version version;

    std::shared_ptr<AbstractTxEncryptor> crypto_util;

    // must only be set by set_current_domain, since it affects current_writer
    SecurityDomain current_domain;

    template <typename T>
    void serialise_internal(T&& t)
    {
      current_writer->append(std::forward<T>(t));
    }

    template <typename T>
    void serialise_internal_public(T&& t)
    {
      public_writer.append(std::forward<T>(t));
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
      std::shared_ptr<AbstractTxEncryptor> e, const Version& version_) :
      crypto_util(e)
    {
      set_current_domain(SecurityDomain::PUBLIC);
      serialise_internal(version_);
      version = version_;
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

    template <class Version>
    void serialise_read_version(const Version& version)
    {
      serialise_internal(version);
    }

    void serialise_count_header(uint64_t ctr)
    {
      serialise_internal(ctr);
    }

    template <class K>
    void serialise_read(const K& k, const Version& version)
    {
      serialise_internal(k);
      serialise_internal(version);
    }

    template <class K, class V>
    void serialise_write(const K& k, const V& v)
    {
      serialise_internal(k);
      serialise_internal(v);
    }

    template <class K, class V, class Version>
    void serialise_write_version(const K& k, const V& v, const Version& version)
    {
      serialise_internal(KvOperationType::KOT_WRITE_VERSION);
      serialise_internal(k);
      serialise_internal(v);
      serialise_internal(version);
    }

    template <class K>
    void serialise_remove_version(const K& k)
    {
      serialise_internal(KvOperationType::KOT_REMOVE_VERSION);
      serialise_internal(k);
    }

    template <class K>
    void serialise_remove(const K& k)
    {
      serialise_internal(k);
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
        version);

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
    Version version;
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

  public:
    GenericDeserialiseWrapper(
      std::shared_ptr<AbstractTxEncryptor> e,
      std::optional<SecurityDomain> domain_restriction) :
      crypto_util(e),
      domain_restriction(domain_restriction),
      unhandled_op(KvOperationType::KOT_NOT_SUPPORTED)
    {}

    bool init(const uint8_t* data, size_t size)
    {
      current_reader = &public_reader;
      auto data_ = data;
      auto size_ = size;

      // If the kv store has no encryptor, assume that the serialised tx is
      // public only with no header
      if (!crypto_util)
      {
        public_reader.init(data, size);
        return true;
      }

      // Skip gcm hdr and read length of public domain
      serialized::skip(data_, size_, crypto_util->get_header_length());
      auto public_domain_length = serialized::read<size_t>(data_, size_);

      // Set public reader
      auto data_public = data_;
      public_reader.init(data_public, public_domain_length);

      // If the domain is public only, skip the decryption and only return the
      // public data
      if (
        domain_restriction.has_value() &&
        domain_restriction.value() == kv::SecurityDomain::PUBLIC)
        return true;

      // Read version without modifying public reader
      version = public_reader.template peek_next<Version>();

      // Go to start of private domain
      serialized::skip(data_, size_, public_domain_length);
      decrypted_buffer.resize(size_);

      if (!crypto_util->decrypt(
            {data_, data_ + size_},
            {data_public, data_public + public_domain_length},
            {data, data + crypto_util->get_header_length()},
            decrypted_buffer,
            version))
      {
        return false;
      }

      // Set private reader
      private_reader.init(decrypted_buffer.data(), decrypted_buffer.size());
      return true;
    }

    template <class Version>
    Version deserialise_version()
    {
      version = current_reader->template read_next<Version>();
      return version;
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

    template <class Version>
    Version deserialise_read_version()
    {
      return current_reader->template read_next<Version>();
    }

    uint64_t deserialise_read_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    template <class K>
    std::tuple<K, Version> deserialise_read()
    {
      return {current_reader->template read_next<K>(),
              current_reader->template read_next<Version>()};
    }

    uint64_t deserialise_write_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    template <class K, class V>
    std::tuple<K, V> deserialise_write()
    {
      return {current_reader->template read_next<K>(),
              current_reader->template read_next<V>()};
    }

    uint64_t deserialise_remove_header()
    {
      return current_reader->template read_next<uint64_t>();
    }

    template <class K>
    K deserialise_remove()
    {
      return current_reader->template read_next<K>();
    }

    template <class K, class V, class Version>
    std::optional<KeyValVersion<K, V, Version>> deserialise_write_version()
    {
      if (end())
        return {};

      auto curr_op = try_read_op_flag(
        KvOperationType::KOT_WRITE_VERSION |
        KvOperationType::KOT_REMOVE_VERSION);

      switch (curr_op)
      {
        case KvOperationType::KOT_WRITE_VERSION:
        {
          K key = current_reader->template read_next<K>();
          V value = current_reader->template read_next<V>();
          Version version = current_reader->template read_next<Version>();
          return {{key, value, version, false}};
        }
        case KvOperationType::KOT_REMOVE_VERSION:
        {
          K key = current_reader->template read_next<K>();
          return {{key, V(), Version(), true}};
        }
        default:
          return {};
      }
    }

    bool end()
    {
      return current_reader->is_eos() && public_reader.is_eos();
    }
  };
}
