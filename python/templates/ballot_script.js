{%- from "macros.jinja" import json_encode as json_encode -%}
export function vote (rawProposal, proposerId) {
  let proposal = JSON.parse(rawProposal);
  if (!('actions' in proposal))
  {
    return false;
  }

  let actions = proposal['actions'];
  if (actions.length !== {{ actions|length }} )
  {
    return false;
  }
{% for action in actions %}
  {
    let action = actions[{{ loop.index - 1}}];
    if (!('name' in action) || !('args' in action))
    {
      return false;
    }

    if (action.name !== '{{ action.name }}')
    {
      return false;
    }

    let args = action.args;
{% if actions.args is defined and actions.args is mapping %}{% for arg_name, arg_value in action.args.items() %}    { 
      if (!('{{ arg_name }}' in args))
      {
        return false;
      }

      const expected = {{ json_encode(arg_value) }};
      if (args['{{ arg_name }}']) !== expected)
      {
        return false;
      }
    } {% endfor %}{% endif %}
  }
{% endfor %}
  return true;
}