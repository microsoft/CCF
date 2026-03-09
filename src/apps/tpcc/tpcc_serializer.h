// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"

namespace tpcc
{
  struct DbCreation
  {
    int32_t new_orders_per_district;
    int32_t seed;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(new_orders_per_district) + sizeof(seed);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, new_orders_per_district);
      serialized::write(data, size, seed);
      return v;
    }

    static DbCreation deserialize(const uint8_t* data, size_t size)
    {
      DbCreation db;
      db.new_orders_per_district =
        serialized::read<decltype(new_orders_per_district)>(data, size);
      db.seed = serialized::read<decltype(seed)>(data, size);
      return db;
    }
  };

  struct StockLevel
  {
    int32_t seed;
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(seed) + sizeof(warehouse_id) + sizeof(district_id) +
        sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, seed);
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static StockLevel deserialize(const uint8_t* data, size_t size)
    {
      StockLevel db;
      db.seed = serialized::read<decltype(seed)>(data, size);
      db.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      db.district_id = serialized::read<decltype(district_id)>(data, size);
      db.threshold = serialized::read<decltype(threshold)>(data, size);
      return db;
    }
  };

  struct TxInfo
  {
    int32_t seed;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(seed);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, seed);
      return v;
    }

    static TxInfo deserialize(const uint8_t* data, size_t size)
    {
      TxInfo info;
      info.seed = serialized::read<decltype(seed)>(data, size);
      return info;
    }
  };
}
