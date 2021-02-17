const actions = new Map([
  [
    "set_recovery_threshold",
    function (args) {
      return Number.isInteger(args.threshold) && args.threshold > 0 && args.threshold < 255 
    }
  ]
])

export function validate(input) {
  let proposal = JSON.parse(input)
  let errors = []
  for (const action of proposal)
  {
    const validator = actions.get(action.name);
    if (validator)
    {
      if (!validator(action.args))
      {
        errors.push(action.name + " failed validation")
      }
    }
    else
    {
      errors.push(action.name + ": no such action")
    }
  }
  return { valid: errors.length == 0, description: errors.join("\n") }
}