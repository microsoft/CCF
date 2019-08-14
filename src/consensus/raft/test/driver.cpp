// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "driver.h"

#include "ds/hash.h"

#include <cassert>
#include <iostream>
#include <regex>
#include <string>

using namespace std;

constexpr auto shash = ds::fnv_1a<size_t>;

int main(int argc, char** argv)
{
  const regex delim{","};
  string line;
  size_t lineno = 1;
  auto driver = shared_ptr<RaftDriver>(nullptr);

  while (getline(cin, line))
  {
    line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
    vector<string> items{
      sregex_token_iterator(line.begin(), line.end(), delim, -1),
      std::sregex_token_iterator()};
    switch (shash(items[0].c_str()))
    {
      case shash("nodes"):
        assert(items.size() == 2);
        driver = make_shared<RaftDriver>(stoi(items[1]));
        break;
      case shash("connect"):
        assert(items.size() == 3);
        driver->connect(stoi(items[1]), stoi(items[2]));
        break;
      case shash("periodic_one"):
        assert(items.size() == 3);
        driver->periodic_one(stoi(items[1]), ms(stoi(items[2])));
        break;
      case shash("periodic_all"):
        assert(items.size() == 2);
        driver->periodic_all(ms(stoi(items[1])));
        break;
      case shash("state_one"):
        assert(items.size() == 2);
        driver->state_one(stoi(items[1]));
        break;
      case shash("dispatch_all"):
        assert(items.size() == 1);
        driver->dispatch_all();
        break;
      case shash("dispatch_all_once"):
        assert(items.size() == 1);
        driver->dispatch_all_once();
        break;
      case shash("state_all"):
        assert(items.size() == 1);
        driver->state_all();
        break;
      case shash("replicate"):
        assert(items.size() == 4);
        driver->replicate(
          stoi(items[1]),
          stoi(items[2]),
          vector<uint8_t>(items[3].begin(), items[3].end()));
        break;
      case shash("disconnect"):
        assert(items.size() == 3);
        driver->disconnect(stoi(items[1]), stoi(items[2]));
        break;
      case shash("disconnect_node"):
        assert(items.size() == 2);
        driver->disconnect_node(stoi(items[1]));
        break;
      case shash("reconnect"):
        assert(items.size() == 3);
        driver->reconnect(stoi(items[1]), stoi(items[2]));
        break;
      case shash("reconnect_node"):
        assert(items.size() == 2);
        driver->reconnect_node(stoi(items[1]));
        break;
      default:
        cerr << "Unknown action '" << items[0] << "' at line " << lineno
             << endl;
    }
    ++lineno;
  }

  return 0;
}
