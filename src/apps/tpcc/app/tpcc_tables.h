// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/nonstd.h"
#include "ccf/kv/map.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ds/serialized.h"
#include "tpcc_common.h"

#include <cstring>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tpcc
{
  template <typename T>
  kv::serialisers::SerialisedEntry tpcc_serialise(const T& t);

  template <typename T>
  T tpcc_deserialise(const kv::serialisers::SerialisedEntry& rep);

  template <typename T>
  constexpr size_t serialised_size()
  {
    if constexpr (ccf::nonstd::is_std_array<T>::value)
    {
      return std::tuple_size_v<T> * serialised_size<typename T::value_type>();
    }
    else
    {
      return sizeof(T);
    }
  }

  template <typename T>
  void write_value(const T& v, uint8_t*& data, size_t& size)
  {
    if constexpr (ccf::nonstd::is_std_array<T>::value)
    {
      if constexpr (std::is_integral_v<typename T::value_type>)
      {
        serialized::write(
          data, size, (const uint8_t*)v.data(), serialised_size<T>());
      }
      else
      {
        for (const auto& e : v)
        {
          write_value(e, data, size);
        }
      }
    }
    else
    {
      serialized::write(data, size, v);
    }
  }

  template <typename T>
  void read_value(T& v, const uint8_t*& data, size_t& size)
  {
    if constexpr (ccf::nonstd::is_std_array<T>::value)
    {
      if constexpr (std::is_integral_v<typename T::value_type>)
      {
        constexpr auto n = serialised_size<T>();
        memcpy(v.data(), data, n);
        serialized::skip(data, size, n);
      }
      else
      {
        for (auto& e : v)
        {
          read_value(e, data, size);
        }
      }
    }
    else
    {
      v = serialized::read<T>(data, size);
    }
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define ADD_SERIALIZED_SIZE_FOR_JSON_NEXT(TYPE, FIELD) \
  +serialised_size<decltype(TYPE::FIELD)>()
#define ADD_SERIALIZED_SIZE_FOR_JSON_FINAL(TYPE, FIELD) \
  ADD_SERIALIZED_SIZE_FOR_JSON_NEXT(TYPE, FIELD)

#define WRITE_VALUE_FOR_JSON_NEXT(TYPE, FIELD) write_value(t.FIELD, data, size);
#define WRITE_VALUE_FOR_JSON_FINAL(TYPE, FIELD) \
  WRITE_VALUE_FOR_JSON_NEXT(TYPE, FIELD)

#define READ_VALUE_FOR_JSON_NEXT(TYPE, FIELD) read_value(t.FIELD, data, size);
#define READ_VALUE_FOR_JSON_FINAL(TYPE, FIELD) \
  READ_VALUE_FOR_JSON_NEXT(TYPE, FIELD)

#define DECLARE_TPCC_TYPE(TYPE)
#define DECLARE_TPCC_REQUIRED_FIELDS(TYPE, ...) \
  _Pragma("clang diagnostic push"); \
  _Pragma("clang diagnostic ignored \"-Wgnu-zero-variadic-macro-arguments\""); \
  template <> \
  kv::serialisers::SerialisedEntry tpcc_serialise(const TYPE& t) \
  { \
    kv::serialisers::SerialisedEntry rep; \
    constexpr size_t required_size = 0 _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      ADD_SERIALIZED_SIZE, TYPE, ##__VA_ARGS__); \
    rep.resize(required_size); \
    auto data = rep.data(); \
    auto size = rep.size(); \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(WRITE_VALUE, TYPE, ##__VA_ARGS__); \
    return rep; \
  } \
  template <> \
  TYPE tpcc_deserialise(const kv::serialisers::SerialisedEntry& rep) \
  { \
    auto data = rep.data(); \
    auto size = rep.size(); \
    TYPE t; \
    _FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)(READ_VALUE, TYPE, ##__VA_ARGS__); \
    return t; \
  } \
  _Pragma("clang diagnostic pop");
#pragma clang diagnostic pop

  template <typename T>
  struct TpccSerialiser
  {
    static kv::serialisers::SerialisedEntry to_serialised(const T& t)
    {
      return tpcc_serialise(t);
    }

    static T from_serialised(const kv::serialisers::SerialisedEntry& rep)
    {
      return tpcc_deserialise<T>(rep);
    }
  };

  namespace Address
  {
    static const int MIN_STREET = 10;
    static const int MAX_STREET = 20;
    static const int MIN_CITY = 10;
    static const int MAX_CITY = 20;
    static const int STATE = 2;
    static const int ZIP = 9;
  };

  struct Item
  {
    static const int MIN_IM = 1;
    static const int MAX_IM = 10000;
    static constexpr float MIN_PRICE = 1.00;
    static constexpr float MAX_PRICE = 100.00;
    static const int MIN_NAME = 14;
    static const int MAX_NAME = 24;
    static const int MIN_DATA = 26;
    static const int MAX_DATA = 50;
    static const int NUM_ITEMS = 100000;

    struct Key
    {
      int32_t id;
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    int32_t im_id;
    float price;
    std::array<char, MAX_NAME + 1> name = {0};
    std::array<char, MAX_DATA + 1> data = {0};
  };
  DECLARE_TPCC_TYPE(Item::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(Item::Key, id);
  DECLARE_TPCC_TYPE(Item);
  DECLARE_TPCC_REQUIRED_FIELDS(Item, id, im_id, price, name, data);

  struct Warehouse
  {
    static constexpr float MIN_TAX = 0;
    static constexpr float MAX_TAX = 0.2000f;
    static constexpr float INITIAL_YTD = 300000.00f;
    static const int MIN_NAME = 6;
    static const int MAX_NAME = 10;
    // TPC-C 1.3.1 (page 11) requires 2*W. This permits testing up to 50
    // warehouses. This is an arbitrary limit created to pack ids into integers.
    static const int MAX_WAREHOUSE_ID = 100;
    struct Key
    {
      int32_t id;
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    float tax;
    float ytd;
    std::array<char, MAX_NAME + 1> name = {0};
    std::array<char, Address::MAX_STREET + 1> street_1 = {0};
    std::array<char, Address::MAX_STREET + 1> street_2 = {0};
    std::array<char, Address::MAX_STREET + 1> city = {0};
    std::array<char, Address::STATE + 1> state = {0};
    std::array<char, Address::ZIP + 1> zip = {0};
  };
  DECLARE_TPCC_TYPE(Warehouse::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(Warehouse::Key, id);
  DECLARE_TPCC_TYPE(Warehouse);
  DECLARE_TPCC_REQUIRED_FIELDS(
    Warehouse, id, tax, ytd, name, street_1, street_2, city, state, zip);

  struct District
  {
    static constexpr float MIN_TAX = 0;
    static constexpr float MAX_TAX = 0.2000f;
    static constexpr float INITIAL_YTD = 30000.00;
    static const int INITIAL_NEXT_O_ID = 3001;
    static const int MIN_NAME = 6;
    static const int MAX_NAME = 10;
    static const int NUM_PER_WAREHOUSE = 10;

    struct Key
    {
      int32_t id;
      int32_t w_id;
    };

    int32_t id;
    int32_t w_id;
    float tax;
    float ytd;
    int32_t next_o_id;
    std::array<char, MAX_NAME + 1> name = {0};
    std::array<char, Address::MAX_STREET + 1> street_1 = {0};
    std::array<char, Address::MAX_STREET + 1> street_2 = {0};
    std::array<char, Address::MAX_CITY + 1> city = {0};
    std::array<char, Address::STATE + 1> state = {0};
    std::array<char, Address::ZIP + 1> zip = {0};

    Key get_key()
    {
      return {id, w_id};
    }
  };

  DECLARE_TPCC_TYPE(District::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(District::Key, id, w_id);
  DECLARE_TPCC_TYPE(District);
  DECLARE_TPCC_REQUIRED_FIELDS(
    District,
    id,
    w_id,
    tax,
    ytd,
    next_o_id,
    name,
    street_1,
    street_2,
    city,
    state,
    zip);

  struct Stock
  {
    static const int MIN_QUANTITY = 10;
    static const int MAX_QUANTITY = 100;
    static const int DIST = 24;
    static const int MIN_DATA = 26;
    static const int MAX_DATA = 50;
    static const int NUM_STOCK_PER_WAREHOUSE = 100000;

    int32_t i_id;
    int32_t w_id;
    int32_t quantity;
    int32_t ytd;
    int32_t order_cnt;
    int32_t remote_cnt;
    std::array<std::array<char, DIST + 1>, District::NUM_PER_WAREHOUSE> dist =
      {};
    std::array<char, MAX_DATA + 1> data = {0};

    struct Key
    {
      int32_t i_id;
      int32_t w_id;
    };

    Key get_key()
    {
      return {i_id, w_id};
    }
  };
  DECLARE_TPCC_TYPE(Stock::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(Stock::Key, i_id, w_id);
  DECLARE_TPCC_TYPE(Stock);
  DECLARE_TPCC_REQUIRED_FIELDS(
    Stock, i_id, w_id, quantity, ytd, order_cnt, remote_cnt, dist, data);

  struct Customer
  {
    static constexpr float INITIAL_CREDIT_LIM = 50000.00;
    static constexpr float MIN_DISCOUNT = 0.0000;
    static constexpr float MAX_DISCOUNT = 0.5000;
    static constexpr float INITIAL_BALANCE = -10.00;
    static constexpr float INITIAL_YTD_PAYMENT = 10.00;
    static const int INITIAL_PAYMENT_CNT = 1;
    static const int INITIAL_DELIVERY_CNT = 0;
    static const int MIN_FIRST = 6;
    static const int MAX_FIRST = 10;
    static const int MIDDLE = 2;
    static const int MAX_LAST = 16;
    static const int PHONE = 16;
    static const int CREDIT = 2;
    static const int MIN_DATA = 300;
    static const int MAX_DATA = 500;
    static const int NUM_PER_DISTRICT = 3000;
    static constexpr char GOOD_CREDIT[] = "GC";
    static constexpr char BAD_CREDIT[] = "BC";

    struct Key
    {
      int32_t id;
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    int32_t d_id;
    int32_t w_id;
    float credit_lim;
    float discount;
    float balance;
    float ytd_payment;
    int32_t payment_cnt;
    int32_t delivery_cnt;
    std::array<char, MAX_FIRST + 1> first = {0};
    std::array<char, MIDDLE + 1> middle = {0};
    std::array<char, MAX_LAST + 1> last = {0};
    std::array<char, Address::MAX_STREET + 1> street_1 = {0};
    std::array<char, Address::MAX_STREET + 1> street_2 = {0};
    std::array<char, Address::MAX_CITY + 1> city = {0};
    std::array<char, Address::STATE + 1> state = {0};
    std::array<char, Address::ZIP + 1> zip = {0};
    std::array<char, PHONE + 1> phone = {0};
    std::array<char, DATETIME_SIZE + 1> since = {0};
    std::array<char, CREDIT + 1> credit = {0};
    std::array<char, MAX_DATA + 1> data = {0};
  };

  DECLARE_TPCC_TYPE(Customer::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(Customer::Key, id);
  DECLARE_TPCC_TYPE(Customer);
  DECLARE_TPCC_REQUIRED_FIELDS(
    Customer,
    id,
    d_id,
    w_id,
    credit_lim,
    discount,
    balance,
    ytd_payment,
    payment_cnt,
    delivery_cnt,
    first,
    middle,
    last,
    street_1,
    street_2,
    city,
    state,
    zip,
    phone,
    since,
    credit,
    data);

  struct Order
  {
    static const int MIN_CARRIER_ID = 1;
    static const int MAX_CARRIER_ID = 10;
    static const int NULL_CARRIER_ID = 0;
    static const int NULL_CARRIER_LOWER_BOUND = 2101;
    static const int MIN_OL_CNT = 5;
    static const int MAX_OL_CNT = 15;
    static const int INITIAL_ALL_LOCAL = 1;
    static const int INITIAL_ORDERS_PER_DISTRICT = 3000;
    // See TPC-C 1.3.1 (page 15)
    static const int MAX_ORDER_ID = 10000000;

    struct Key
    {
      int32_t id;
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    int32_t c_id;
    int32_t d_id;
    int32_t w_id;
    int32_t carrier_id;
    int32_t ol_cnt;
    int32_t all_local;
    std::array<char, DATETIME_SIZE + 1> entry_d = {0};
  };
  DECLARE_TPCC_TYPE(Order::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(Order::Key, id);
  DECLARE_TPCC_TYPE(Order);
  DECLARE_TPCC_REQUIRED_FIELDS(
    Order, id, c_id, d_id, w_id, carrier_id, ol_cnt, all_local, entry_d);

  struct OrderLine
  {
    static const int MIN_I_ID = 1;
    static const int MAX_I_ID = 100;
    static const int INITIAL_QUANTITY = 5;
    static constexpr float MIN_AMOUNT = 0.01f;
    static constexpr float MAX_AMOUNT = 9999.99f;
    static const int REMOTE_PROBABILITY_MILLIS = 10;

    struct Key
    {
      int32_t o_id;
      int32_t d_id;
      int32_t w_id;
      int32_t number;
    };

    Key get_key()
    {
      return {o_id, d_id, w_id, number};
    }

    int32_t o_id;
    int32_t d_id;
    int32_t w_id;
    int32_t number;
    int32_t i_id;
    int32_t supply_w_id;
    int32_t quantity;
    float amount;
    std::array<char, DATETIME_SIZE + 1> delivery_d = {0};
    std::array<char, Stock::DIST + 1> dist_info = {0};
  };

  DECLARE_TPCC_TYPE(OrderLine::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(OrderLine::Key, o_id, d_id, w_id, number);
  DECLARE_TPCC_TYPE(OrderLine);
  DECLARE_TPCC_REQUIRED_FIELDS(
    OrderLine,
    o_id,
    d_id,
    w_id,
    number,
    i_id,
    supply_w_id,
    quantity,
    amount,
    delivery_d,
    dist_info);

  struct NewOrder
  {
    static const int INITIAL_NUM_PER_DISTRICT = 900;

    struct Key
    {
      int32_t w_id;
      int32_t d_id;
      int32_t o_id;
    };

    Key get_key()
    {
      return {w_id, d_id, o_id};
    }

    int32_t w_id;
    int32_t d_id;
    int32_t o_id;
  };
  DECLARE_TPCC_TYPE(NewOrder::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(NewOrder::Key, w_id, d_id, o_id);
  DECLARE_TPCC_TYPE(NewOrder);
  DECLARE_TPCC_REQUIRED_FIELDS(NewOrder, w_id, d_id, o_id);

  struct History
  {
    static const int MIN_DATA = 12;
    static const int MAX_DATA = 24;
    static constexpr float INITIAL_AMOUNT = 10.00f;

    struct Key
    {
      int32_t c_id;
      int32_t c_d_id;
      int32_t c_w_id;
      int32_t d_id;
      int32_t w_id;
    };

    Key get_key()
    {
      return {c_id, c_d_id, c_w_id, d_id, w_id};
    }

    int32_t c_id;
    int32_t c_d_id;
    int32_t c_w_id;
    int32_t d_id;
    int32_t w_id;
    float amount;
    std::array<char, DATETIME_SIZE + 1> date = {0};
    std::array<char, MAX_DATA + 1> data = {0};
  };
  DECLARE_TPCC_TYPE(History::Key);
  DECLARE_TPCC_REQUIRED_FIELDS(History::Key, c_id, c_d_id, c_w_id, d_id, w_id);
  DECLARE_TPCC_TYPE(History);
  DECLARE_TPCC_REQUIRED_FIELDS(
    History, c_id, c_d_id, c_w_id, d_id, w_id, amount, date, data);

  template <typename K, typename V>
  using TpccMap = kv::MapSerialisedWith<K, V, TpccSerialiser>;

  struct TpccTables
  {
    union DistributeKey
    {
      struct
      {
        int32_t w_id;
        int32_t d_id;
      } v;
      uint64_t k;
    };
    static_assert(
      sizeof(DistributeKey) == sizeof(uint64_t),
      "Distribute key is the wrong size");

    static TpccMap<Stock::Key, Stock> stocks;
    static TpccMap<Warehouse::Key, Warehouse> warehouses;
    static TpccMap<District::Key, District> districts;
    static TpccMap<History::Key, History> histories;
    static std::unordered_map<uint64_t, TpccMap<Customer::Key, Customer>>
      customers;
    static std::unordered_map<uint64_t, TpccMap<Order::Key, Order>> orders;
    static TpccMap<OrderLine::Key, OrderLine> order_lines;
    static std::unordered_map<uint64_t, TpccMap<NewOrder::Key, NewOrder>>
      new_orders;
    static TpccMap<Item::Key, Item> items;
  };
}