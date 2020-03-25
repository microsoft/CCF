// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "ds/files.h"
#include "new_principal.h"

#include <CLI11/CLI11.hpp>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <iostream>
#include <memory.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int resolvehelper(
  const char* hostname,
  int family,
  const char* service,
  sockaddr_storage* pAddr)
{
  int result;
  addrinfo* result_list = NULL;
  addrinfo hints = {};
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  result = getaddrinfo(hostname, service, &hints, &result_list);
  if (result == 0)
  {
    memcpy(pAddr, result_list->ai_addr, result_list->ai_addrlen);
    freeaddrinfo(result_list);
  }

  return result;
}

int main(int argc, char** argv)
{
  CLI::App app{"Run Replica Test"};

  // run tests
  NodeId id = 0;
  app.add_option("--id", id, "id");

  short port = 0;
  app.add_option("--port", port, "port");

  std::string ip;
  app.add_option("--ip", ip, "ip");

  std::string cert_file;
  app.add_option("--cert_file", cert_file, "cert file");

  std::string host_name;
  app.add_option("--host_name", host_name, "host_name");

  bool is_replica;
  app.add_flag("--is_replica", is_replica, "is_replica");

  CLI11_PARSE(app, argc, argv);

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  sockaddr_in addrListen = {};
  addrListen.sin_family = AF_INET;
  int result = bind(sock, (sockaddr*)&addrListen, sizeof(addrListen));
  if (result == -1)
  {
    int lasterror = errno;
    std::cout << "error: " << lasterror;
    exit(1);
  }

  sockaddr_storage addrDest = {};
  result = resolvehelper(ip.c_str(), AF_INET, "3000", &addrDest);
  if (result != 0)
  {
    int lasterror = errno;
    std::cout << "error: " << lasterror;
    exit(1);
  }

  auto node_cert = files::slurp_string(cert_file);
  New_principal msg(id, port, ip, node_cert, host_name, is_replica);

  result = sendto(
    sock,
    msg.contents(),
    msg.size(),
    0,
    (sockaddr*)&addrDest,
    sizeof(addrDest));

  std::cout << result << " bytes sent" << std::endl;

  return 0;
}
