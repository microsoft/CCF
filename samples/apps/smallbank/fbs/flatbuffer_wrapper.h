// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"

#include <smallbank_generated.h>

class FlatbufferSerializer
{
protected:
  flatbuffers::FlatBufferBuilder builder;

public:
  std::unique_ptr<flatbuffers::DetachedBuffer> get_detached_buffer()
  {
    return std::make_unique<flatbuffers::DetachedBuffer>(builder.Release());
  }

  CBuffer get_buffer()
  {
    return {builder.GetBufferPointer(), builder.GetSize()};
  }
};

class TransactionSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<Transaction> transaction;

public:
  TransactionSerializer(const std::string& name, const int value)
  {
    transaction = CreateTransaction(builder, builder.CreateString(name), value);
    builder.Finish(transaction);
  }
};

class TransactionDeserializer
{
private:
  const Transaction* root;

public:
  TransactionDeserializer(const uint8_t* data) :
    root(flatbuffers::GetRoot<Transaction>(data))
  {}

  std::string name()
  {
    return root->name()->str();
  }

  int value()
  {
    return root->value();
  }
};

class AmalgamateSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<Amalgamate> amalgamate;

public:
  AmalgamateSerializer(
    const std::string& name_src, const std::string& name_dest)
  {
    amalgamate = CreateAmalgamate(
      builder, builder.CreateString(name_src), builder.CreateString(name_dest));
    builder.Finish(amalgamate);
  }
};

class AmalgamateDeserializer
{
private:
  const Amalgamate* root;

public:
  AmalgamateDeserializer(const uint8_t* data) :
    root(flatbuffers::GetRoot<Amalgamate>(data))
  {}

  std::string name_src()
  {
    return root->name_src()->str();
  }

  std::string name_dest()
  {
    return root->name_dest()->str();
  }
};

class AccountsSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<Accounts> accounts;

public:
  AccountsSerializer(
    const uint64_t from,
    const uint64_t to,
    const int64_t checking_amt,
    const int64_t savings_amt)
  {
    accounts = CreateAccounts(builder, from, to, checking_amt, savings_amt);
    builder.Finish(accounts);
  }
};

class AccountsDeserializer
{
private:
  const Accounts* root;

public:
  AccountsDeserializer(const uint8_t* data) :
    root(flatbuffers::GetRoot<Accounts>(data))
  {}
  uint64_t from()
  {
    return root->from();
  }

  uint64_t to()
  {
    return root->to();
  }

  int64_t checking_amt()
  {
    return root->checking_amt();
  }

  int64_t savings_amt()
  {
    return root->savings_amt();
  }
};

class BankSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<Bank> bank;

public:
  BankSerializer(const std::string& name)
  {
    bank = CreateBank(builder, builder.CreateString(name));
    builder.Finish(bank);
  }
};

class BankDeserializer
{
private:
  const Bank* root;

public:
  BankDeserializer(const uint8_t* data) : root(flatbuffers::GetRoot<Bank>(data))
  {}

  std::string name()
  {
    return root->name()->str();
  }

  uint64_t id()
  {
    return root->id();
  }

  int64_t checking_amt()
  {
    return root->checking_amt();
  }

  int64_t savings_amt()
  {
    return root->savings_amt();
  }
};

class BalanceSerializer : public FlatbufferSerializer
{
private:
  flatbuffers::Offset<Balance> balance;

public:
  BalanceSerializer(const int64_t b)
  {
    balance = CreateBalance(builder, b);
    builder.Finish(balance);
  }
};

class BalanceDeserializer
{
private:
  const Balance* root;

public:
  BalanceDeserializer(const uint8_t* data) :
    root(flatbuffers::GetRoot<Balance>(data))
  {}

  int64_t balance()
  {
    return root->balance();
  }
};