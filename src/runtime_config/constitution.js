const actions = new Map([
  [
    "set_recovery_threshold",
    function (args) {
      return Integer.isInteger(args.threshold) && args.threshold > 0 && args.threshold < 255 
    }
  ]
])

export function validate(input) {
  let proposal = JSON.parse(input)
  let errors = []
  for (const action of actions)
  {
    const validator = actions.get(action.name);
    if (validator && !validator(action.args))
    {
      errors.push(action.name + " failed validation")
    }
    else
    {
      errors.push(action.name + ": no such action")
    }
  }
  return { valid: errors, description: errors.join("\n") }
}