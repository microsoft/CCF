// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "ds/logger.h"
#include "itimer.h"
#include "message.h"
#include "network.h"
#include "parameters.h"
#include "replica.h"

#include <atomic>
#include <cstdlib>
#include <fcntl.h>
#include <mutex>
#include <stdexcept>
#include <thread>

struct MessageDesc
{
  uint32_t size;
  int pid;
  Auth_type auth_type;
  int auth_len;
  int dst_offset;
  int src_offset;
  MessageDesc* next;

  // followed by a buffer with size bytes
  void* get_buf()
  {
    return (void*)((uintptr_t)this + sizeof(MessageDesc));
  }
};

template <class T>
class MessageQueue
{
public:
  MessageQueue();
  void queue(T* desc);
  T* dequeue_list();

private:
  std::atomic<T*> head;
};

class SenderThread
{
public:
  SenderThread(unsigned short port_offset);
  void queue_for_replica(MessageDesc* desc);
  void queue_for_client(MessageDesc* desc);

private:
  void Work();
  MessageDesc* dequeue(
    MessageDesc*& local_list, MessageQueue<MessageDesc>* queue);
  MessageDesc* dequeue_for_replica();
  MessageDesc* dequeue_for_client();
  void send_message(int sock, MessageDesc* message, unsigned short port_offset);

  static int create_socket();

  int sock_replicas;
  unsigned short port_offset;
  std::unique_ptr<MessageQueue<MessageDesc>> msg_queue_replicas;
  MessageDesc* local_list_replicas;

  int sock_clients;
  std::unique_ptr<MessageQueue<MessageDesc>> msg_queue_clients;
  MessageDesc* local_list_clients;

  std::thread* sender_thread;
};

class ReceiverThread
{
public:
  ReceiverThread(in_port_t port, int index);
  void queue(Message* m);
  Message* dequeue();
  bool has_items();

private:
  void Work();

  int sock;
  std::unique_ptr<MessageQueue<Message>> msg_queue;
  Message* local_list;
  std::thread* receiver_thread;
  int index;
};

class UDPNetworkMultiThreaded : public INetwork
{
public:
  UDPNetworkMultiThreaded(unsigned short port_offset);
  virtual ~UDPNetworkMultiThreaded() = default;

  virtual bool Initialize(in_port_t port);
  virtual int Send(Message* msg, IPrincipal& principal);
  virtual Message* GetNextMessage();
  virtual bool has_messages(long to);

private:
  unsigned short port_offset;
  size_t next_thread;
  std::vector<std::unique_ptr<SenderThread>> sending_threads;

  static const size_t num_receivers =
    num_receivers_replicas + num_receivers_clients;
  size_t next_replica_to_poll;
  size_t next_client_to_poll;

  std::vector<std::unique_ptr<ReceiverThread>> receiving_threads;
};

UDPNetworkMultiThreaded::UDPNetworkMultiThreaded(unsigned short port_offset) :
  port_offset(port_offset),
  next_replica_to_poll(0),
  next_client_to_poll(0)
{}

bool UDPNetworkMultiThreaded::Initialize(in_port_t port)
{
  // initialize sender threads
  next_thread = 0;
  for (size_t i = 0; i < num_senders; i++)
  {
    sending_threads.emplace_back(std::make_unique<SenderThread>(port_offset));
  }

  // initialize receiver threads
  in_port_t port_base = ntohs(port);
  for (size_t i = 0; i < num_receivers; i++)
  {
    receiving_threads.emplace_back(
      std::make_unique<ReceiverThread>(port_base + (unsigned short)i, (int)i));
  }

  return true;
}

int UDPNetworkMultiThreaded::Send(Message* msg, IPrincipal& principal)
{
  // see if it is possible to avoid this copy and pool the allocation
  auto message = new (malloc(msg->size() + sizeof(MessageDesc))) MessageDesc;
  message->size = msg->size();
  message->pid = principal.pid();
  memcpy(message->get_buf(), msg->contents(), msg->size());

  next_thread++;
  if (principal.is_replica())
  {
    sending_threads[next_thread % num_senders]->queue_for_replica(message);
  }
  else
  {
    sending_threads[next_thread % num_senders]->queue_for_client(message);
  }

  return (int)msg->size();
}

Message* UDPNetworkMultiThreaded::GetNextMessage()
{
  while (1)
  {
    ITimer::handle_timeouts();

    size_t index = next_replica_to_poll++ % num_receivers_replicas;
    Message* m = receiving_threads[index]->dequeue();
    if (m != nullptr)
    {
      return m;
    }

    if (index == 0)
    {
      m = receiving_threads
            [num_receivers_replicas +
             next_client_to_poll++ % num_receivers_clients]
              ->dequeue();
      if (m != nullptr)
      {
        return m;
      }
    }
  }
}

bool UDPNetworkMultiThreaded::has_messages(long to)
{
  ITimer::handle_timeouts();

  for (size_t i = 0; i < num_receivers; i++)
  {
    if (receiving_threads[i]->has_items())
    {
      return true;
    }
  }

  return false;
}

template <class T>
MessageQueue<T>::MessageQueue() : head(nullptr)
{}

template <class T>
void MessageQueue<T>::queue(T* desc)
{
  T* old_head = head.load(std::memory_order_relaxed);

  do
  {
    desc->next = old_head;
  } while (!head.compare_exchange_strong(old_head, desc));
}

template <class T>
T* MessageQueue<T>::dequeue_list()
{
  T* old_head = head.load(std::memory_order_relaxed);

  if (old_head == nullptr)
  {
    return nullptr;
  }

  T* list;
  do
  {
    list = old_head;
  } while (!head.compare_exchange_strong(old_head, nullptr));

  return list;
}

SenderThread::SenderThread(unsigned short port_offset) :
  port_offset(port_offset),
  local_list_replicas(nullptr),
  local_list_clients(nullptr)
{
  sock_clients = create_socket();
  msg_queue_clients.reset(
    new (aligned_alloc(64, std::max(sizeof(MessageQueue<MessageDesc>), 64UL)))
      MessageQueue<MessageDesc>);

  sock_replicas = create_socket();
  msg_queue_replicas.reset(
    new (aligned_alloc(64, std::max(sizeof(MessageQueue<MessageDesc>), 64UL)))
      MessageQueue<MessageDesc>);

  auto thread_func = [](SenderThread* _this) { _this->Work(); };

  sender_thread = new std::thread(thread_func, this);
}

int SenderThread::create_socket()
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    perror("unable to create socket");
    exit(1);
  }

  // name the socket
  sockaddr_in tmp;
  tmp.sin_family = AF_INET;
  tmp.sin_addr.s_addr = htonl(INADDR_ANY);
  tmp.sin_port = 0;
  int error = bind(sock, (struct sockaddr*)&tmp, sizeof(sockaddr_in));
  if (error < 0)
  {
    perror("Unable to name socket");
    exit(1);
  }

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
  return sock;
}

void SenderThread::queue_for_replica(MessageDesc* desc)
{
  msg_queue_replicas->queue(desc);
}

void SenderThread::queue_for_client(MessageDesc* desc)
{
  msg_queue_clients->queue(desc);
}

MessageDesc* SenderThread::dequeue(
  MessageDesc*& local_list, MessageQueue<MessageDesc>* queue)
{
  if (local_list == nullptr)
  {
    local_list = queue->dequeue_list();
  }

  if (local_list != nullptr)
  {
    auto ret = local_list;
    local_list = ret->next;
    return ret;
  }

  return nullptr;
}

MessageDesc* SenderThread::dequeue_for_replica()
{
  return dequeue(local_list_replicas, msg_queue_replicas.get());
}

MessageDesc* SenderThread::dequeue_for_client()
{
  return dequeue(local_list_clients, msg_queue_clients.get());
}

void SenderThread::send_message(
  int sock, MessageDesc* message, unsigned short port_offset)
{
  std::shared_ptr<Principal> p =
    pbft::GlobalState::get_node().get_principal(message->pid);
  if (p != nullptr)
  {
    sockaddr_in to = *(sockaddr_in*)p->address();
    if (port_offset != 0)
    {
      to.sin_port = htons(ntohs(to.sin_port) + port_offset);
    }

    ssize_t ret = sendto(
      sock,
      message->get_buf(),
      message->size,
      0,
      (sockaddr*)&to,
      sizeof(sockaddr_in));

    if (ret != message->size)
    {
      LOG_FATAL << "failed to send correctly, expected:" << message->size
                << ", actual:" << ret << std::endl;
    }
  }
}

void SenderThread::Work()
{
  while (true)
  {
    auto message = dequeue_for_replica();
    if (message != nullptr)
    {
      send_message(sock_replicas, message, port_offset);
      free(message);
    }
    else
    {
      message = dequeue_for_client();
      if (message != nullptr)
      {
        send_message(sock_clients, message, 0);
        free(message);
      }
    }
  }
}

ReceiverThread::ReceiverThread(in_port_t port, int index) :
  local_list(nullptr),
  index(index)
{
  // Initialize receive socket.
  sock = socket(AF_INET, SOCK_DGRAM, 0);

  // name the socket
  sockaddr_in tmp;
  tmp.sin_family = AF_INET;
  tmp.sin_addr.s_addr = htonl(INADDR_ANY);
  tmp.sin_port = htons(port);
  int error = bind(sock, (struct sockaddr*)&tmp, sizeof(sockaddr_in));
  if (error < 0)
  {
    perror("Unable to name socket");
    exit(1);
  }

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

  msg_queue.reset(new (aligned_alloc(
    64, std::max(sizeof(MessageQueue<Message>), 64UL))) MessageQueue<Message>);

  auto thread_func = [](ReceiverThread* _this) { _this->Work(); };

  receiver_thread = new std::thread(thread_func, this);
}

bool ReceiverThread::has_items()
{
  if (local_list == nullptr)
  {
    local_list = msg_queue->dequeue_list();
  }

  return local_list != nullptr;
}

void ReceiverThread::queue(Message* m)
{
  msg_queue->queue(m);
}

Message* ReceiverThread::dequeue()
{
  if (local_list == nullptr)
  {
    local_list = msg_queue->dequeue_list();
  }

  if (local_list != nullptr)
  {
    auto ret = local_list;
    local_list = ret->next;
    return ret;
  }

  return nullptr;
}

void ReceiverThread::Work()
{
  std::unique_ptr<uint8_t[]> buffer =
    std::make_unique<uint8_t[]>(Max_message_size);
  while (true)
  {
    int ret =
      recvfrom(sock, buffer.get(), Message::get_size(buffer.get()), 0, 0, 0);

    if (ret < sizeof(Message_rep))
    {
      continue;
    }
    Message* m =
      Replica::create_message(buffer.get(), Message::get_size(buffer.get()));

    LOG_TRACE << " Received tag: " << m->tag() << " at thread index: " << index
              << std::endl;

    if (
      m != nullptr && ret >= (int)sizeof(Message_rep) &&
      ret >= (int)m->size() && Replica::pre_verify(m))
    {
      queue(m);
      continue;
    }

    delete m;
  }
}

std::unique_ptr<INetwork> Create_UDP_Network_MultiThreaded(
  unsigned short port_offset)
{
  return std::make_unique<UDPNetworkMultiThreaded>(port_offset);
}
