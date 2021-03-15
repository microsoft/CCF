// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstring>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
namespace tpcc
{
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
      MSGPACK_DEFINE(id);
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    int32_t im_id;
    float price;
    std::array<char, MAX_NAME + 1> name;
    std::array<char, MAX_DATA + 1> data;

    MSGPACK_DEFINE(id, im_id, price, name, data);
  };
  DECLARE_JSON_TYPE(Item::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Item::Key, id);
  DECLARE_JSON_TYPE(Item);
  DECLARE_JSON_REQUIRED_FIELDS(Item, id, im_id, price, name, data);

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
      MSGPACK_DEFINE(id);
    };

    Key get_key()
    {
      return {id};
    }

    int32_t id;
    float tax;
    float ytd;
    std::array<char, MAX_NAME + 1> name;
    std::array<char, Address::MAX_STREET + 1> street_1;
    std::array<char, Address::MAX_STREET + 1> street_2;
    std::array<char, Address::MAX_STREET + 1> city;
    std::array<char, Address::STATE + 1> state;
    std::array<char, Address::ZIP + 1> zip;

    MSGPACK_DEFINE(id, tax, ytd, name, street_1, street_2, city, state, zip);
  };
  DECLARE_JSON_TYPE(Warehouse::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Warehouse::Key, id);
  DECLARE_JSON_TYPE(Warehouse);
  DECLARE_JSON_REQUIRED_FIELDS(
    Warehouse, id, tax, ytd, name, street_1, street_2, city, state, zip);

  struct District
  {
    static constexpr float MIN_TAX = 0;
    static constexpr float MAX_TAX = 0.2000f;
    static constexpr float INITIAL_YTD = 30000.00; // different from Warehouse
    static const int INITIAL_NEXT_O_ID = 3001;
    static const int MIN_NAME = 6;
    static const int MAX_NAME = 10;
    static const int NUM_PER_WAREHOUSE = 10;

    struct Key
    {
      int32_t id;
      int32_t w_id;
      MSGPACK_DEFINE(id, w_id);
    };

    int32_t id;
    int32_t w_id;
    float tax;
    float ytd;
    int32_t next_o_id;
    std::array<char, MAX_NAME + 1> name;
    std::array<char, Address::MAX_STREET + 1> street_1;
    std::array<char, Address::MAX_STREET + 1> street_2;
    std::array<char, Address::MAX_CITY + 1> city;
    std::array<char, Address::STATE + 1> state;
    std::array<char, Address::ZIP + 1> zip;

    Key get_key()
    {
      return {id, w_id};
    }

    MSGPACK_DEFINE(
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
  };
  DECLARE_JSON_TYPE(District::Key);
  DECLARE_JSON_REQUIRED_FIELDS(District::Key, id, w_id);
  DECLARE_JSON_TYPE(District);
  DECLARE_JSON_REQUIRED_FIELDS(
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
    std::array<std::array<char, DIST + 1>, District::NUM_PER_WAREHOUSE> dist;
    std::array<char, MAX_DATA + 1> data;

    Stock() = default;

    struct Key
    {
      int32_t i_id;
      int32_t w_id;
      MSGPACK_DEFINE(i_id, w_id);
    };

    Key get_key()
    {
      return {i_id, w_id};
    }

    MSGPACK_DEFINE(
      i_id, w_id, quantity, ytd, order_cnt, remote_cnt, dist, data);
  };
  DECLARE_JSON_TYPE(Stock::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Stock::Key, i_id, w_id);
  DECLARE_JSON_TYPE(Stock);
  DECLARE_JSON_REQUIRED_FIELDS(
    Stock, i_id, w_id, quantity, ytd, order_cnt, remote_cnt, dist, data);

  // YYYY-MM-DD HH:MM:SS This is supposed to be a date/time field from Jan 1st
  // 1900 - Dec 31st 2100 with a resolution of 1 second. See TPC-C 1.3.1.
  static const int DATETIME_SIZE = 14;

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
      MSGPACK_DEFINE(id);
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
    std::array<char, MAX_FIRST + 1> first;
    std::array<char, MIDDLE + 1> middle;
    std::array<char, MAX_LAST + 1> last;
    std::array<char, Address::MAX_STREET + 1> street_1;
    std::array<char, Address::MAX_STREET + 1> street_2;
    std::array<char, Address::MAX_CITY + 1> city;
    std::array<char, Address::STATE + 1> state;
    std::array<char, Address::ZIP + 1> zip;
    std::array<char, PHONE + 1> phone;
    std::array<char, DATETIME_SIZE + 1> since;
    std::array<char, CREDIT + 1> credit;
    std::array<char, MAX_DATA + 1> data;

    MSGPACK_DEFINE(
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
  };
  DECLARE_JSON_TYPE(Customer::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Customer::Key, id);
  DECLARE_JSON_TYPE(Customer);
  DECLARE_JSON_REQUIRED_FIELDS(
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
      MSGPACK_DEFINE(id);
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
    std::array<char, DATETIME_SIZE + 1> entry_d;

    MSGPACK_DEFINE(
      id, c_id, d_id, w_id, carrier_id, ol_cnt, all_local, entry_d);
  };
  DECLARE_JSON_TYPE(Order::Key);
  DECLARE_JSON_REQUIRED_FIELDS(Order::Key, id);
  DECLARE_JSON_TYPE(Order);
  DECLARE_JSON_REQUIRED_FIELDS(
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
      MSGPACK_DEFINE(o_id, d_id, w_id, number);
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
    std::array<char, DATETIME_SIZE + 1> delivery_d;
    std::array<char, Stock::DIST + 1> dist_info;

    MSGPACK_DEFINE(
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
  };
  DECLARE_JSON_TYPE(OrderLine::Key);
  DECLARE_JSON_REQUIRED_FIELDS(OrderLine::Key, o_id, d_id, w_id, number);
  DECLARE_JSON_TYPE(OrderLine);
  DECLARE_JSON_REQUIRED_FIELDS(
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
      MSGPACK_DEFINE(w_id, d_id, o_id);
    };

    Key get_key()
    {
      return {w_id, d_id, o_id};
    }

    int32_t w_id;
    int32_t d_id;
    int32_t o_id;

    MSGPACK_DEFINE(w_id, d_id, o_id);
  };
  DECLARE_JSON_TYPE(NewOrder::Key);
  DECLARE_JSON_REQUIRED_FIELDS(NewOrder::Key, w_id, d_id, o_id);
  DECLARE_JSON_TYPE(NewOrder);
  DECLARE_JSON_REQUIRED_FIELDS(NewOrder, w_id, d_id, o_id);

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
      MSGPACK_DEFINE(c_id, c_d_id, c_w_id, d_id, w_id);
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
    std::array<char, DATETIME_SIZE + 1> date;
    std::array<char, MAX_DATA + 1> data;

    MSGPACK_DEFINE(c_id, c_d_id, c_w_id, d_id, w_id, amount, date, data);
  };
  DECLARE_JSON_TYPE(History::Key);
  DECLARE_JSON_REQUIRED_FIELDS(History::Key, c_id, c_d_id, c_w_id, d_id, w_id);
  DECLARE_JSON_TYPE(History);
  DECLARE_JSON_REQUIRED_FIELDS(
    History, c_id, c_d_id, c_w_id, d_id, w_id, amount, date, data);

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

    static kv::Map<Stock::Key, Stock> stocks;
    static kv::Map<Warehouse::Key, Warehouse> warehouses;
    static kv::Map<District::Key, District> districts;
    static kv::Map<History::Key, History> histories;
    static std::unordered_map<uint64_t, kv::Map<Customer::Key, Customer>>
      customers;
    static std::unordered_map<uint64_t, kv::Map<Order::Key, Order>> orders;
    static kv::Map<OrderLine::Key, OrderLine> order_lines;
    static std::unordered_map<uint64_t, kv::Map<NewOrder::Key, NewOrder>>
      new_orders;
    static kv::Map<Item::Key, Item> items;
  };
}