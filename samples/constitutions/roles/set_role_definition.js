// A simple wrapper for set usage in the KV in the constitution
class KVSet {
  #map;

  constructor(map) {
    this.#map = map;
  }

  has(key) {
    return this.#map.has(key);
  }

  add(key) {
    this.#map.set(key, new ArrayBuffer(8));
  }

  delete(key) {
    this.#map.delete(key);
  }

  clear() {
    this.#map.clear();
  }

  asSet() {
    let set = new Set();
    this.#map.forEach((_, key) => set.add(key));
    return set;
  }
}

actions.set(
  "set_role_definition",
  new Action(
    function (args) {
      checkType(args.role, "string", "role");
      checkType(args.actions, "array", "actions");
      for (const [i, action] of args.actions.entries()) {
        checkType(action, "string", `actions[${i}]`);
      }
    },
    function (args) {
      let roleDefinition = new KVSet(
        ccf.kv[`public:ccf.gov.roles.${args.role}`],
      );
      let oldValues = roleDefinition.asSet();
      let newValues = new Set(args.actions);
      // Can't do that in QuickJS
      for (const action of oldValues.difference(newValues)) {
        roleDefinition.delete(action);
      }
      for (const action of newValues.difference(oldValues)) {
        roleDefinition.add(action);
      }
    },
  ),
);
