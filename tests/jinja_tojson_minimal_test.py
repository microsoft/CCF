import json
from jinja2 import Environment


def render_tojson(value):
    env = Environment(autoescape=False)
    template = env.from_string("{{ value | tojson }}")
    return template.render(value=value)


def test_tojson_for_list_of_objects():
    value = [
        {"foo": "bar", "baz": "a"},
        {"foo": "foobar", "baz": "b"},
    ]

    rendered = render_tojson(value)

    assert json.loads(rendered) == value


if __name__ == "__main__":
    test_value = [
        {"foo": "bar", "baz": "a"},
        {"foo": "foobar", "baz": "b"},
    ]
    print(render_tojson(test_value))
