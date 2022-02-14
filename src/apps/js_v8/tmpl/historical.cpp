// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "historical.h"

#include "ccf/ds/logger.h"
#include "historical_state.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    StateCache,
    END
  };

  static ccf::historical::AbstractStateCache* unwrap_state_cache(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::historical::AbstractStateCache*>(
      get_internal_field(obj, InternalField::StateCache));
  }

  static void get_state_range(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::historical::AbstractStateCache* state_cache =
      unwrap_state_cache(info.Holder());

    if (info.Length() != 4)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 4", info.Length()));
      return;
    }

    v8::Local<v8::Value> arg1 = info[0];
    v8::Local<v8::Value> arg2 = info[1];
    v8::Local<v8::Value> arg3 = info[2];
    v8::Local<v8::Value> arg4 = info[3];
    if (
      !arg1->IsNumber() || !arg2->IsNumber() || !arg3->IsNumber() ||
      !arg4->IsNumber())
    {
      v8_util::throw_type_error(isolate, "Arguments must be numbers");
      return;
    }
    v8::Local<v8::Number> handle_v8 = arg1.As<v8::Number>();
    v8::Local<v8::Number> start_seqno_v8 = arg2.As<v8::Number>();
    v8::Local<v8::Number> end_seqno_v8 = arg3.As<v8::Number>();
    v8::Local<v8::Number> seconds_until_expiry_v8 = arg4.As<v8::Number>();

    int64_t handle;
    int64_t start_seqno;
    int64_t end_seqno;
    int64_t seconds_until_expiry;
    if (!handle_v8->IntegerValue(context).To(&handle))
      return;
    if (!start_seqno_v8->IntegerValue(context).To(&start_seqno))
      return;
    if (!end_seqno_v8->IntegerValue(context).To(&end_seqno))
      return;
    if (!seconds_until_expiry_v8->IntegerValue(context).To(
          &seconds_until_expiry))
      return;
    if (
      handle < 0 || start_seqno < 0 || end_seqno < 0 ||
      seconds_until_expiry < 0)
    {
      v8_util::throw_range_error(
        isolate, "Invalid handle or seqno or expiry: cannot be negative");
      return;
    }

    ccf::View view;
    ccf::SeqNo seqno;
    std::vector<ccf::historical::StatePtr> states;
    try
    {
      states = state_cache->get_state_range(
        handle,
        start_seqno,
        end_seqno,
        std::chrono::seconds(seconds_until_expiry));
    }
    catch (std::exception& exc)
    {
      v8_util::throw_error(isolate, fmt::format("Error: {}", exc.what()));
      return;
    }

    if (states.empty())
    {
      info.GetReturnValue().Set(v8::Null(isolate));
      return;
    }

    std::vector<v8::Local<v8::Value>> v8_states;
    v8_states.reserve(states.size());
    for (auto& state : states)
    {
      v8_states.push_back(HistoricalState::wrap(context, state));
    }

    v8::Local<v8::Array> v8_states_array =
      v8::Array::New(isolate, v8_states.data(), v8_states.size());

    info.GetReturnValue().Set(v8_states_array);
  }

  static void drop_cached_states(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ccf::historical::AbstractStateCache* state_cache =
      unwrap_state_cache(info.Holder());

    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }

    v8::Local<v8::Value> arg1 = info[0];
    if (!arg1->IsNumber())
    {
      v8_util::throw_type_error(isolate, "Argument must be a number");
      return;
    }
    v8::Local<v8::Number> handle_v8 = arg1.As<v8::Number>();

    int64_t handle;
    if (!handle_v8->IntegerValue(context).To(&handle))
      return;
    if (handle < 0)
    {
      v8_util::throw_range_error(isolate, "Invalid handle: cannot be negative");
      return;
    }

    auto found = state_cache->drop_cached_states(handle);
    v8::Local<v8::Value> value = v8::Boolean::New(isolate, found);

    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> Historical::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "getStateRange"),
      v8::FunctionTemplate::New(isolate, get_state_range));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "dropCachedStates"),
      v8::FunctionTemplate::New(isolate, drop_cached_states));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Historical::wrap(
    v8::Local<v8::Context> context,
    ccf::historical::AbstractStateCache* state_cache)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Historical>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::StateCache, state_cache}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl
