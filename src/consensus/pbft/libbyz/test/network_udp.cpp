// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ds/logger.h"
#include "itimer.h"
#include "libbyz.h"
#include "message.h"
#include "network.h"
#include "replica.h"

#include <fcntl.h>

class UDPNetwork : public INetwork
{
public:
  UDPNetwork(unsigned short port_offset) : port_offset(port_offset) {}
  virtual ~UDPNetwork() = default;

  virtual bool Initialize(in_port_t port)
  {
    // Initialize socket.
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    // name the socket
    sockaddr_in tmp;
    tmp.sin_family = AF_INET;
    tmp.sin_addr.s_addr = htonl(INADDR_ANY);
    tmp.sin_port = port;
    int error = bind(sock, (struct sockaddr*)&tmp, sizeof(sockaddr_in));
    if (error < 0)
    {
      perror("Unable to name socket");
      exit(1);
    }

    //#define NO_UDP_CHECKSUM
#ifdef NO_UDP_CHECKSUM
    int no_check = 1;
    error = setsockopt(
      sock, SOL_SOCKET, SO_NO_CHECK, (char*)&no_check, sizeof(no_check));
    if (error < 0)
    {
      perror("unable to turn of UDP checksumming");
      exit(1);
    }
#endif // NO_UDP_CHECKSUM

#define LARGE_SND_BUFF
#ifdef LARGE_SND_BUFF
    int snd_buf_size = 262144;
    error = setsockopt(
      sock, SOL_SOCKET, SO_SNDBUF, (char*)&snd_buf_size, sizeof(snd_buf_size));
    if (error < 0)
    {
      perror("unable to increase send buffer size");
      exit(1);
    }
#endif

#define LARGE_RCV_BUFF
#ifdef LARGE_RCV_BUFF
    int rcv_buf_size = 131072;
    error = setsockopt(
      sock, SOL_SOCKET, SO_RCVBUF, (char*)&rcv_buf_size, sizeof(rcv_buf_size));
    if (error < 0)
    {
      perror("unable to increase send buffer size");
      exit(1);
    }
#endif

#define ASYNC_SOCK
#ifdef ASYNC_SOCK
    error = fcntl(sock, F_SETFL, O_NONBLOCK);

    if (error < 0)
    {
      perror("unable to set socket to asynchronous mode");
      exit(1);
    }
#endif // ASYNC_SOCK

    return true;
  }

  virtual int Send(Message* msg, IPrincipal& principal)
  {
    sockaddr_in to = *(sockaddr_in*)principal.address();
    if (port_offset != 0)
    {
      to.sin_port = htons(ntohs(to.sin_port) + port_offset);
    }

    int error = sendto(
      sock,
      msg->contents(),
      msg->size(),
      0,
      (sockaddr*)&to,
      sizeof(sockaddr_in));
    if (error == -1 || error != msg->size())
    {
      int err = errno;
      LOG_FAIL << "error sending, errno:" << err << ", size:" << msg->size()
               << ", sent_size:" << error << std::endl;
    }

    return error;
  }

  std::unique_ptr<uint8_t[]> buffer =
    std::make_unique<uint8_t[]>(Max_message_size);

  virtual Message* GetNextMessage()
  {
    while (1)
    {
      while (!has_messages(20000))
      {
        ;
      }
      int ret = recvfrom(sock, buffer.get(), Max_message_size, 0, 0, 0);
      if (ret < sizeof(Message_rep))
      {
        continue;
      }
      Message* m =
        Replica::create_message(buffer.get(), Message::get_size(buffer.get()));
      if (
        m != nullptr && ret >= (int)sizeof(Message_rep) &&
        ret >= (int)m->size() && Replica::pre_verify(m))
      {
        return m;
      }

      delete m;
    }
  }

  virtual bool has_messages(long to)
  {
    ITimer::handle_timeouts();

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = to;
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    int ret = select(sock + 1, &fdset, 0, 0, &timeout);
    if (ret > 0 && FD_ISSET(sock, &fdset))
    {
      return true;
    }
    return false;
  }

private:
  int sock = INT_MAX;
  unsigned short port_offset;
};

std::unique_ptr<INetwork> Create_UDP_Network(unsigned short port_offset = 0)
{
  return std::make_unique<UDPNetwork>(port_offset);
}
