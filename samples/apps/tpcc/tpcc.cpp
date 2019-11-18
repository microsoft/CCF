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
    Store::Map<std::string, Warehouse>& warehouses;
    Store::Map<std::string, District>& districts;
    Store::Map<std::string, Customer>& customers;
    Store::Map<std::string, History>& histories;
    Store::Map<std::string, NewOrder>& neworders;
    Store::Map<std::string, Order>& orders;
    Store::Map<std::string, OrderLine>& orderlines;
    Store::Map<std::string, Item>& items;
    Store::Map<std::string, Stock>& stocks;

  public:
    Tpcc(Store& tables) :
      UserRpcFrontend(tables),
      warehouses(tables.create<std::string, Warehouse>("warehouses")),
      districts(tables.create<std::string, District>("districts")),
      customers(tables.create<std::string, Customer>("customers")),
      histories(tables.create<std::string, History>("histories")),
      neworders(tables.create<std::string, NewOrder>("neworders")),
      orders(tables.create<std::string, Order>("orders")),
      orderlines(tables.create<std::string, OrderLine>("orderlines")),
      items(tables.create<std::string, Item>("items")),
      stocks(tables.create<std::string, Stock>("stocks"))
    {
      
    }
  };

  std::shared_ptr<enclave::RpcHandler> get_rpc_handler(
    NetworkTables& nwt, AbstractNotifier& notifier)
  {
    return std::make_shared<Tpcc>(nwt, notifier);
  }

} // namespace tpcc
} // namespace ccfapp
