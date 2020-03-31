// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "../src/consensus/consensus_types.h"
#include "ds/logger.h"
#include "message.h"
#include "node.h"
#include "parameters.h"
#include "time_types.h"
#include "types.h"

#include <bitset>
#include <sys/time.h>

template <class T>
class Certificate
{
  //
  // A certificate is a set of "matching" messages from different
  // replicas.
  //
  // T must have the following methods:
  // bool match(T*);
  // // Effects: Returns true iff the messages match
  //
  // int id();
  // // Effects: Returns the identifier of the principal that
  // // sent the message.
  //
  // bool verify();
  // // Effects: Returns true iff the message is properly authenticated
  // // and statically correct.
  //
  // bool full();
  // // Effects: Returns true iff the message is full

public:
  Certificate(std::function<int()> complete = nullptr);
  // Requires: "complete" >= f+1 or 0
  // Effects: Creates an empty certificate. The certificate is
  // complete when it contains at least "complete" matching messages
  // from different replicas. If the complete argument is omitted (or
  // 0) it is taken to be 2f+1.

  Certificate(
    size_t f,
    size_t num_correct_replicas,
    std::function<int()> complete = nullptr);

  ~Certificate();
  // Effects: Deletes certificate and all the messages it contains.

  bool add(T* msg);
  // Effects: Adds "msg" to the certificate and returns true provided
  // "msg" satisfies:
  // 1. there is no message from "msg.id()" in the certificate
  // 2. "msg->verify() == true"
  // 3. if "cvalue() != 0", "cvalue()->match(msg)";
  // otherwise, it has no effect on this and returns false.  This
  // becomes the owner of "msg" (i.e., no other code should delete "msg"
  // or retain pointers to "msg".)

  bool has_message_from_replica(int id) const;

  bool add_mine(T* msg);
  // Requires: The identifier of the calling principal is "msg->id()"
  // and "mine()==0" and msg is full.
  // Effects: If "cvalue() != 0" and "!cvalue()->match(msg)", it has no
  // effect and returns false. Otherwise, adds "msg" to the certificate
  // and returns. This becomes the owner of "msg"

  T* mine();
  T* mine(Time& t);
  // Effects: Returns caller's message in certificate or 0 if there is
  // no such message. If "t" is supplied, sets it to point to the time
  // at which I last sent my message to all replicas.

  T* cvalue() const;
  // Effects: Returns the correct message value for this certificate
  // or 0 if this value is not known. Note that the certificate
  // retains ownership over the returned value (e.g., if clear or
  // mark_stale are called the value may be deleted.)

  T* cvalue_clear();
  // Effects: Returns the correct message value for this certificate
  // or 0 if this value is not known. If it returns the correct value,
  // it removes the message from the certificate and clears the
  // certificate (that is the caller gains ownership over the returned
  // value.)

  int num_correct() const;
  // Effects: Returns the number of messages with the correct value
  // in this.

  int num_complete() const;
  bool is_complete() const;
  void make_complete();
  // Effects: If cvalue() is not null, makes the certificate
  // complete.

  void update();
  // Effects: reset f if needed

  void mark_stale();
  // Effects: Discards all messages in certificate except mine.

  void clear();
  // Effects: Discards all messages in certificate

  bool is_empty() const;
  // Effects: Returns true iff the certificate is empty

  class Val_iter
  {
    // An iterator for yielding all the distinct values in a
    // certificate and the number of messages matching each value. The
    // certificate cannot be modified while it is being iterated on.
  public:
    Val_iter(Certificate<T>* c);
    // Effects: Return an iterator for the values in "c"

    bool get(T*& msg, int& count);
    // Effects: Updates "msg" to point to the next value in the
    // certificate and count to contain the number of messages
    // matching this value and returns true. If there are no more
    // values, it returns false.

  private:
    Certificate<T>* cert;
    int next;
  };
  friend class Val_iter;

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

private:
  std::bitset<Max_num_replicas>
    bmap; // bitmap with replicas whose message is in this.

  class Message_val
  {
  public:
    T* msg;
    int count;

    inline Message_val()
    {
      msg = 0;
      count = 0;
    }
    inline void clear()
    {
      delete msg;
      msg = 0;
      count = 0;
    }
    inline ~Message_val()
    {
      clear();
    }
  };

  Message_val* vals; // vector with all distinct message values in this
  int max_size; // maximum number of elements in vals, f+1
  int cur_size; // current number of elements in vals

  int correct; // value is correct if it appears in at least "correct" messages
  Message_val* c; // correct certificate value or 0 if unknown.

  int complete; // certificate is complete if "num_correct() >= complete"
  std::function<int()>
    comp; // the value of complete as sent into the ctor through a function so
          // if f() changes it can be recalculated

  T* mym; // my message in this or null if I have no message in this
  Time t_sent; // time at which mym was last sent

  ccf::NodeId f; // the value of f when starting to run

  // The implementation assumes:
  // correct > 0 and complete > correct

  void reset_f(); // If sets the f and associated values used when f has changed
                  // between the cert is created and when it is first used
};

template <class T>
inline T* Certificate<T>::mine(Time& t)
{
  update();
  if (mym)
  {
    t = t_sent;
  }
  return mym;
}

template <class T>
inline T* Certificate<T>::mine()
{
  update();
  return mym;
}

template <class T>
inline T* Certificate<T>::cvalue() const
{
  return (c) ? c->msg : 0;
}

template <class T>
inline int Certificate<T>::num_correct() const
{
  return (c) ? c->count : 0;
}

template <class T>
inline int Certificate<T>::num_complete() const
{
  return complete;
}

template <class T>
inline void Certificate<T>::update()
{
  if (bmap.none() && f != pbft::GlobalState::get_node().f())
  {
    reset_f();
  }
}

template <class T>
inline bool Certificate<T>::is_complete() const
{
  return num_correct() >= complete;
}

template <class T>
inline bool Certificate<T>::has_message_from_replica(int id) const
{
  return bmap.test(id);
}

template <class T>
inline void Certificate<T>::make_complete()
{
  if (c)
  {
    c->count = complete;
  }
}

template <class T>
inline bool Certificate<T>::is_empty() const
{
  return bmap.none();
}

template <class T>
inline void Certificate<T>::clear()
{
  for (int i = 0; i < cur_size; i++)
    vals[i].clear();
  bmap.reset();
  c = 0;
  mym = 0;
  t_sent = 0;
  cur_size = 0;
}

template <class T>
inline Certificate<T>::Val_iter::Val_iter(Certificate<T>* c)
{
  cert = c;
  next = 0;
}

template <class T>
inline bool Certificate<T>::Val_iter::get(T*& msg, int& count)
{
  if (next < cert->cur_size)
  {
    msg = cert->vals[next].msg;
    count = cert->vals[next].count;
    next++;
    return true;
  }
  return false;
}

template <class T>
Certificate<T>::Certificate(
  size_t f_, size_t num_correct_replicas, std::function<int()> comp_) :
  f(f_),
  comp(comp_)
{
  max_size = f + 1;
  vals = new Message_val[max_size];
  cur_size = 0;
  correct = f + 1;
  if (comp_ != nullptr)
  {
    complete = comp_();
  }
  else
  {
    complete = num_correct_replicas;
  }
  c = 0;
  mym = 0;
  t_sent = 0;
}

template <class T>
Certificate<T>::Certificate(std::function<int()> comp_) :
  Certificate(
    pbft::GlobalState::get_node().f(),
    pbft::GlobalState::get_node().num_correct_replicas(),
    comp_)
{}

template <class T>
Certificate<T>::~Certificate()
{
  delete[] vals;
}

template <class T>
void Certificate<T>::reset_f()
{
  f = pbft::GlobalState::get_node().f();
  max_size = f + 1;
  delete[] vals;
  vals = new Message_val[max_size];
  cur_size = 0;
  correct = f + 1;
  if (comp != nullptr)
  {
    complete = comp();
  }
  else
  {
    complete = pbft::GlobalState::get_node().num_correct_replicas();
  }
}

template <class T>
bool Certificate<T>::add(T* msg)
{
  auto principal = pbft::GlobalState::get_node().get_principal(msg->id());
  if (!principal)
  {
    LOG_INFO_FMT(
      "Principal with id {} has not been configured yet, rejecting the message",
      msg->id());
    delete msg;
    return false;
  }

  if (bmap.none() && f != pbft::GlobalState::get_node().f())
  {
    reset_f();
  }

  const int id = msg->id();

  if (f == 0)
  {
    bmap.set(id);
    Message_val& val = vals[0];
    val.count++;
    c = vals;
    delete c->msg;
    c->msg = msg;
    mym = msg;
    c->count++;
    return true;
  }

  if (pbft::GlobalState::get_node().is_replica(id) && !bmap.test(id))
  {
    // "msg" was sent by a replica that does not have a message in
    // the certificate
    if (
      c == 0 ||
      (c->msg != nullptr && c->count < complete && c->msg->match(msg)))
    {
      // add msg to the certificate
      if (id != pbft::GlobalState::get_node().id())
      {
        LOG_DEBUG_FMT(
          "Adding certificate for replica other than myself, replica id {}",
          id);
      }

      bmap.set(id);
      if (c)
      {
        c->count++;
        if (!c->msg->full() && msg->full())
        {
          // if c->msg is not full and msg is, replace c->msg
          delete c->msg;
          c->msg = msg;
        }
        else
        {
          delete msg;
        }
        return true;
      }

      // Check if there is a value that matches "msg"
      int i;
      for (i = 0; i < cur_size; i++)
      {
        Message_val& val = vals[i];
        if (val.msg->match(msg))
        {
          val.count++;
          if (val.count >= correct)
          {
            c = vals + i;
          }
          if (!val.msg->full() && msg->full())
          {
            // if val.msg is not full and msg is, replace val.msg
            delete val.msg;
            val.msg = msg;
          }
          else
          {
            delete msg;
          }
          return true;
        }
      }

      // "msg" has a new value.
      if (cur_size < max_size)
      {
        vals[cur_size].msg = msg;
        vals[cur_size++].count = 1;
        return true;
      }
      else
      {
        // Should only happen for replies to read-only requests.
        LOG_FAIL << "More than f+1 distinct values in certificate" << std::endl;
        clear();
      }
    }
    else
    {
      bmap.set(id);
    }
  }

  delete msg;
  return false;
}

template <class T>
bool Certificate<T>::add_mine(T* msg)
{
  PBFT_ASSERT(
    msg->id() == pbft::GlobalState::get_node().id(), "Invalid argument");
  PBFT_ASSERT(msg->full(), "Invalid argument");

  if (bmap.none() && f != pbft::GlobalState::get_node().f())
  {
    reset_f();
  }

  if (c != 0 && !c->msg->match(msg))
  {
    PBFT_ASSERT(
      false, "Node is faulty, more than f faulty replicas or faulty primary ");
    LOG_FATAL
      << "Node is faulty, more than f faulty replicas or faulty primary "
      << msg->stag() << std::endl;
    delete msg;
    return false;
  }

  if (c == 0)
  {
    // Set msg to be the correct value.
    int i;
    for (i = 0; i < cur_size; i++)
    {
      if (vals[i].msg->match(msg))
      {
        c = vals + i;
        break;
      }
    }

    if (c == 0)
    {
      c = vals;
      vals->count = 0;
    }
  }

  if (c->msg == 0)
  {
    PBFT_ASSERT(cur_size == 0, "Invalid state");
    cur_size = 1;
  }

  delete c->msg;
  c->msg = msg;
  c->count++;
  mym = msg;
  t_sent = ITimer::current_time();
  return true;
}

template <class T>
void Certificate<T>::mark_stale()
{
  if (!is_complete())
  {
    int i = 0;
    int old_cur_size = cur_size;
    if (mym)
    {
      PBFT_ASSERT(mym == c->msg, "Broken invariant");
      c->msg = 0;
      c->count = 0;
      c = vals;
      c->msg = mym;
      c->count = 1;
      i = 1;
    }
    else
    {
      c = 0;
    }
    cur_size = i;

    for (; i < old_cur_size; i++)
      vals[i].clear();
    bmap.reset();
  }
}

template <class T>
T* Certificate<T>::cvalue_clear()
{
  if (c == 0)
  {
    return 0;
  }

  T* ret = c->msg;
  c->msg = 0;
  for (int i = 0; i < cur_size; i++)
  {
    if (vals[i].msg == ret)
      vals[i].msg = 0;
  }
  clear();

  return ret;
}

template <class T>
void Certificate<T>::dump_state(std::ostream& os)
{
  os << " bmap: " << bmap << " cur_size: " << cur_size
     << " num correct: " << num_correct() << " c: " << (void*)c
     << " is complete: " << is_complete() << " mym: " << (void*)mym
     << " tsent: " << t_sent << std::endl;
}
