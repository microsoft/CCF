// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/openapi.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

void print_doc(const std::string& title, const nlohmann::json& doc)
{
  std::cout << title << std::endl;
  std::cout << doc.dump(2) << std::endl;
}

TEST_CASE("Basic doc")
{
  using namespace ds;
  openapi::Document doc;
  doc.info.title = "Test generated API";
  doc.info.description = "Some longer description enhanced with **Markdown**";
  doc.info.version = "0.1.42";

  {
    openapi::Server mockup_server;
    mockup_server.url =
      "https://virtserver.swaggerhub.com/eddyashton/ccf-test/1.0.0";
    doc.servers.push_back(mockup_server);
  }

  {
    doc.paths["/users/foo"]
      .operations[HTTP_GET]
      .responses[std::to_string(HTTP_STATUS_OK)]
      .description = "Indicates that everything went ok";
  }
  print_doc("PATHS", doc);
}