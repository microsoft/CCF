// Use a different module than the entry module for state testing
// to avoid cases where the entry module is re-loaded
// but not other modules.
import * as a from './a.js';

export function set_module_state(request) {
  a.set_module_state(request.body.json());
  return {};
}

export function get_module_state(request) {
  const state = a.get_module_state();
  return {
    body: state
  };
}

export function set_global_state(request) {
  globalThis.my_state = request.body.json();
  return {};
}

export function get_global_state(request) {
  const state = globalThis.my_state || null;
  return {
    body: state
  };
}

export function override_builtin_property(request) {
  Object.entries = () => ["fake"];
  return {};
}

export function override_ccf_property(request) {
  ccf.bufToStr = () => "modified";
  return {};
}

export function delete_ccf_property(request) {
  delete ccf.bufToStr;
  return {};
}

export function override_ccf_child_property(request) {
  ccf.historical.getStateRange = 42;
  return {};
}

export function check_ccf_child_property(request) {
  if (ccf.historical.getStateRange === 42) {
    throw new Error("ccf.historical.getStateRange is overridden");
  }
  return {};
}
