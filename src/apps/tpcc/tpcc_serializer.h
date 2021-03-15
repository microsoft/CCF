// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"

namespace tpcc
{
  struct TpccDbCreation
  {
    uint32_t num_wh;
    uint32_t num_items;
    int32_t customers_per_district;
    int32_t districts_per_warehouse;
    int32_t new_orders_per_district;

    std::vector<uint8_t> serialize() const
    {
      auto size = sizeof(num_wh) + sizeof(num_items) +
        sizeof(customers_per_district) + sizeof(districts_per_warehouse) +
        sizeof(new_orders_per_district);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, num_wh);
      serialized::write(data, size, num_items);
      serialized::write(data, size, customers_per_district);
      serialized::write(data, size, districts_per_warehouse);
      serialized::write(data, size, new_orders_per_district);
      return v;
    }

    static TpccDbCreation deserialize(const uint8_t* data, size_t size)
    {
      TpccDbCreation a;
      a.num_wh = serialized::read<decltype(num_wh)>(data, size);
      a.num_items = serialized::read<decltype(num_items)>(data, size);
      a.customers_per_district =
        serialized::read<decltype(customers_per_district)>(data, size);
      a.districts_per_warehouse =
        serialized::read<decltype(districts_per_warehouse)>(data, size);
      a.new_orders_per_district =
        serialized::read<decltype(new_orders_per_district)>(data, size);
      return a;
    }
  };

  struct TpccStockLevel
  {
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(warehouse_id) + sizeof(district_id) + sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static TpccStockLevel deserialize(const uint8_t* data, size_t size)
    {
      TpccStockLevel a;
      a.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      a.district_id = serialized::read<decltype(district_id)>(data, size);
      a.threshold = serialized::read<decltype(threshold)>(data, size);
      return a;
    }
  };

  struct TpccOrderStatus
  {
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(warehouse_id) + sizeof(district_id) + sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static TpccOrderStatus deserialize(const uint8_t* data, size_t size)
    {
      TpccOrderStatus a;
      a.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      a.district_id = serialized::read<decltype(district_id)>(data, size);
      a.threshold = serialized::read<decltype(threshold)>(data, size);
      return a;
    }
  };

  struct TpccDelivery
  {
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(warehouse_id) + sizeof(district_id) + sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static TpccDelivery deserialize(const uint8_t* data, size_t size)
    {
      TpccDelivery a;
      a.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      a.district_id = serialized::read<decltype(district_id)>(data, size);
      a.threshold = serialized::read<decltype(threshold)>(data, size);
      return a;
    }
  };

  struct TpccPayment
  {
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(warehouse_id) + sizeof(district_id) + sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static TpccPayment deserialize(const uint8_t* data, size_t size)
    {
      TpccPayment a;
      a.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      a.district_id = serialized::read<decltype(district_id)>(data, size);
      a.threshold = serialized::read<decltype(threshold)>(data, size);
      return a;
    }
  };

  struct TpccNewOrder
  {
    int32_t warehouse_id;
    int32_t district_id;
    int32_t threshold;

    std::vector<uint8_t> serialize() const
    {
      auto size =
        sizeof(warehouse_id) + sizeof(district_id) + sizeof(threshold);
      std::vector<uint8_t> v(size);
      auto data = v.data();
      serialized::write(data, size, warehouse_id);
      serialized::write(data, size, district_id);
      serialized::write(data, size, threshold);
      return v;
    }

    static TpccNewOrder deserialize(const uint8_t* data, size_t size)
    {
      TpccNewOrder a;
      a.warehouse_id = serialized::read<decltype(warehouse_id)>(data, size);
      a.district_id = serialized::read<decltype(district_id)>(data, size);
      a.threshold = serialized::read<decltype(threshold)>(data, size);
      return a;
    }
  };
}
