class Action {
  constructor(validate, apply) {
    this.validate = validate;
    this.apply = apply;
  }
}

const actions = new Map([
  [
    "set_recovery_threshold",
    new Action(
      function (args) {
        return (
          Number.isInteger(args.threshold) &&
          args.threshold > 0 &&
          args.threshold < 255
        );
      },
      function (args, tx) {
        return true;
      }
    ),
  ],
]);

function validate(input) {
  let proposal = JSON.parse(input);
  let errors = [];
  let position = 0;
  for (const action of proposal) {
    const definition = actions.get(action.name);
    if (definition) {
      if (!definition.validate(action.args)) {
        errors.push(`${action.name} at position ${position} failed validation`);
      }
    } else {
      errors.push(`${action.name}: no such action`);
    }
    position++;
  }
  return { valid: errors.length == 0, description: errors.join(", ") };
}

function resolve(proposal, votes) {
  if (votes.length == 0)
  {
    return "Open";
  }
  else
  {
    return "Accepted";
  }
}
