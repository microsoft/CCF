// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "enclave/appinterface.h"
#include "node/rpc/userfrontend.h"
#include "tpcc_entities.h"

using namespace ccf;

namespace ccfapp
{
namespace tpcc
{

  class Tpcc : public ccf::UserRpcFrontend
  {
  private:
    Store::Map<WarehouseId, Warehouse>& warehouses;
    Store::Map<DistrictId, District>& districts;
    Store::Map<CustomerId, Customer>& customers;
    Store::Map<HistoryId, History>& histories;
    Store::Map<NewOrderId, NewOrder>& neworders;
    Store::Map<OrderId, Order>& orders;
    Store::Map<OrderLineId, OrderLine>& orderlines;
    Store::Map<ItemId, Item>& items;
    Store::Map<StockId, Stock>& stocks;

  public:
    Tpcc(Store& tables) :
      UserRpcFrontend(tables),
      warehouses(tables.create<WarehouseId, Warehouse>("warehouses")),
      districts(tables.create<DistrictId, District>("districts")),
      customers(tables.create<CustomerId, Customer>("customers")),
      histories(tables.create<HistoryId, History>("histories")),
      neworders(tables.create<NewOrderId, NewOrder>("neworders")),
      orders(tables.create<OrderId, Order>("orders")),
      orderlines(tables.create<OrderLineId, OrderLine>("orderlines")),
      items(tables.create<ItemId, Item>("items")),
      stocks(tables.create<StockId, Stock>("stocks"))
    {
      
    }
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return std::make_shared<Tpcc>(*nwt.tables);
  }

} // namespace tpcc
} // namespace ccfapp
