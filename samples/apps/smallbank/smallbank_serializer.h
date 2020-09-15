// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"

namespace smallbank
{
  struct Transaction
  {
    std::string name;
    int64_t value;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(name.size()) + name.size() + sizeof(value);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, name);
      serialized::write(data, size, value);
      return v;
    }

    static Transaction deserialize(const uint8_t* data, size_t size)
    {
      Transaction t;
      t.name = serialized::read<decltype(name)>(data, size);
      t.value = serialized::read<decltype(value)>(data, size);
      return t;
    }
  };

  struct Amalgamate
  {
    std::string src;
    std::string dst;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(src.size()) + src.size() + sizeof(dst.size()) + dst.size();
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, src);
      serialized::write(data, size, dst);
      return v;
    }

    static Amalgamate deserialize(const uint8_t* data, size_t size)
    {
      Amalgamate a;
      a.src = serialized::read<decltype(src)>(data, size);
      a.dst = serialized::read<decltype(dst)>(data, size);
      return a;
    }
  };

  struct Balance
  {
    int64_t value;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(value);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, value);
      return v;
    }

    static Balance deserialize(const uint8_t* data, size_t size)
    {
      Balance b;
      b.value = serialized::read<decltype(value)>(data, size);
      return b;
    }
  };

  struct AccountName
  {
    std::string name;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(name.size()) + name.size();
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, name);
      return v;
    }

    static AccountName deserialize(const uint8_t* data, size_t size)
    {
      AccountName a;
      a.name = serialized::read<decltype(name)>(data, size);
      return a;
    }
  };

  struct AccountInfo
  {
    std::string name;
    int64_t checking_amt;
    int64_t savings_amt;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(name.size()) + name.size() + sizeof(checking_amt) +
        sizeof(savings_amt);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, name);
      serialized::write(data, size, checking_amt);
      serialized::write(data, size, savings_amt);
      return v;
    }

    static AccountInfo deserialize(const uint8_t* data, size_t size)
    {
      AccountInfo a;
      a.name = serialized::read<decltype(name)>(data, size);
      a.checking_amt = serialized::read<decltype(checking_amt)>(data, size);
      a.savings_amt = serialized::read<decltype(savings_amt)>(data, size);
      return a;
    }
  };

  struct AccountCreation
  {
    uint64_t new_id_from;
    uint64_t new_id_to;
    int64_t initial_checking_amt;
    int64_t initial_savings_amt;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(new_id_from) + sizeof(new_id_to) +
        sizeof(initial_checking_amt) + sizeof(initial_savings_amt);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, new_id_from);
      serialized::write(data, size, new_id_to);
      serialized::write(data, size, initial_checking_amt);
      serialized::write(data, size, initial_savings_amt);
      return v;
    }

    static AccountCreation deserialize(const uint8_t* data, size_t size)
    {
      AccountCreation a;
      a.new_id_from = serialized::read<decltype(new_id_from)>(data, size);
      a.new_id_to = serialized::read<decltype(new_id_to)>(data, size);
      a.initial_checking_amt =
        serialized::read<decltype(initial_checking_amt)>(data, size);
      a.initial_savings_amt =
        serialized::read<decltype(initial_savings_amt)>(data, size);
      return a;
    }
  };
}
