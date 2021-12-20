let state = { value: 42 };

export function get_module_state() {
  return state;
}

export function set_module_state(s) {
  state = s;
}
