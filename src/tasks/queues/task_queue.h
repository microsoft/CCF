// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

// TODO: This name sucks

namespace ccf::tasks
{
  template <typename T>
  struct Node
  {
    T t;
    Node* next = nullptr;

    Node(const T& t_) : t(t_) {}
  };

  template <typename T>
  struct Queue
  {
    Node<T>* head = nullptr;

    bool add(const T& t)
    {
      Node<T>* node = new Node<T>(t);
      do
      {
        Node<T>* next = head;
        while (next != nullptr)
        {
          next = next->next;
        }

        std::compare_exchange_strong()
      } while (true)
    }

    bool pop_and_process(size_t max_count)
    {
      Node<T>* my_tail = head;
      if (my_tail == nullptr)
      {
        return false;
      }

      size_t i = 0;
      while (my_tail->next != nullptr)
      {
        my_tail = my_tail->next;
        if (++i == max_count)
        {
          break;
        }
      }

      Node<T>* current = head;
      do
      {
        current.t.do();
        current = current->next;
      } while (current != nullptr && current != my_tail);

      std::atomic_exchange(head, my_tail);
    }
  };
}