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
        ccf.kv[`public:programmability.roles.${args.role}`],
      );

      roleDefinition.clear();

      let newValues = new Set(args.actions);
      for (const action of newValues) {
        roleDefinition.add(ccf.jsonCompatibleToBuf(action));
      }
    },
  ),
);
