#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if ! command -v jq &> /dev/null ; then
  echo "This script relies on jq. Please install it first."
  exit 1
fi

STATE_UNDEFINED="undefined"
STATE_ACTION_NAME="parsing action name"
STATE_ARG_NAME="parsing arg name"
STATE_ARG_VALUE="parsing arg value"

ARG_TYPE_STRING="string"
ARG_TYPE_JSON="json"
ARG_TYPE_DEFAULT="$ARG_TYPE_STRING"

current_state="$STATE_UNDEFINED"
current_arg_type="$ARG_TYPE_DEFAULT"
actions="[]"

THIS_SCRIPT="$(basename "$0")"
function usage()
{
  echo "Usage:"
  echo "  $THIS_SCRIPT [--help | --action ACTION_NAME [[FLAGS] ARG_NAME ARG_VALUE...]...]"
}

function print_help()
{
  echo ""
  echo "This tool is a wrapper around jq, to simplify creation of CCF governance"
  echo "proposals."
  echo "Specify a list of actions and associated args. A single flag per argument can be"
  echo "used to indicate how the value should be parsed:"
  echo "  -s String (default)"
  echo "  -j JSON (including objects, numbers and booleans)"
  echo "Additionally, any @-prefixed string is treated as a file path, and will be"
  echo "replaced with the contents of the file."
  echo ""
  args_a=("--action" "set_greeting" "message" "HelloWorld" "-j" "max_repetitions" "42")
  args_b=("--action" "no_arg_action")
  args_c=("--action" "upload_file" "contents" "@file.txt")
  echo "For example:"
  echo "  $THIS_SCRIPT"
  echo "    ${args_a[*]}"
  echo "    ${args_b[*]}"
  echo "    ${args_c[*]}"
  echo ""
  # To keep this help up-to-date, actually run this sample program!
  # But it requires a file, so cheat a little and rewrite that to a temp file
  tmp_file=$(mktemp)
  echo "This is a file." >> "$tmp_file"
  echo "Containing multiple lines." >> "$tmp_file"
  args_c[-1]="@$tmp_file"
  echo "Will produce:"
  $0 "${args_a[@]}" "${args_b[@]}" "${args_c[@]}"
}

function emit_action()
{
  if [ "$current_state" == "$STATE_ACTION_NAME" ]; then
    echo "Missing ACTION_NAME"
    usage
    exit 1
  elif [ "$current_state" == "$STATE_ARG_VALUE" ]; then
    echo "Missing ARG_VALUE"
    usage
    exit 1
  fi
  current_state="$STATE_ACTION_NAME"
  if [ -n "$action" ]; then
    actions="$(jq -n 'input + [input]' <(echo "$action") <(echo "$actions"))"
  fi
}

function consume_action_name()
{
  current_state="$STATE_ARG_NAME"
  action="$(jq -n --arg name "$1" '{name: $name}')"
}

function consume_arg_name()
{
  arg_name="$1"
  current_state="$STATE_ARG_VALUE"
}

function consume_arg_value()
{
  arg_value="$1"
  current_state="$STATE_ARG_NAME"
  jq_val="\$value"
  if [ $current_arg_type == "$ARG_TYPE_JSON" ]; then
    if [ "${arg_value:0:1}" == "@" ]; then
      if [[ ! -a "${arg_value:1}" ]]; then
        echo "Could not find file: ${arg_value:1}"
        exit 1
      fi
      arg_kind="--slurpfile"
      arg_value="${arg_value:1}"
      jq_val="\$value[0]"
    else
      arg_kind="--argjson"
    fi
  else
    arg_kind="--arg"
    if [ "${arg_value:0:1}" == "@" ]; then
      if [[ ! -a "${arg_value:1}" ]]; then
        echo "Could not find file: ${arg_value:1}"
        exit 1
      fi
      # "Command substitutions strip all trailing newlines from the output of the command inside them."
      # So append then strip a single x, to ensure arg_value contains any original trailing newlines verbatim
      arg_value="$(cat ${arg_value:1}; echo x)"
      arg_value="${arg_value%x}"
    fi
  fi
  action="$(echo "$action" | jq --arg name "$arg_name" $arg_kind value "$arg_value" '.args += {($name): '$jq_val'}')"
  current_arg_type="$ARG_TYPE_DEFAULT"
}

function consume_flags()
{
  case "$1" in
    -s)
      current_arg_type="$ARG_TYPE_STRING"
      return 1
      ;;
    -j)
      current_arg_type="$ARG_TYPE_JSON"
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

while [ "$1" != "" ]; do
  if [ "$1" == "--help" ]; then
    usage
    print_help
    exit 0
  elif [ "$1" == "--action" ]; then
    emit_action
  else
    case "$current_state" in
      "$STATE_UNDEFINED")
        usage
        exit 1
        ;;
      "$STATE_ACTION_NAME")
        consume_action_name "$1"
        ;;
      "$STATE_ARG_NAME")
        if ! consume_flags "$1"; then
          shift
        fi
        consume_arg_name "$1"
        ;;
      "$STATE_ARG_VALUE")
        if ! consume_flags "$1"; then
          shift
        fi
        consume_arg_value "$1"
        ;;
    esac
  fi
  shift
done

emit_action

jq -n '{actions: input}' <(echo "$actions")
