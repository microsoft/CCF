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
ARG_TYPE_NUMBER="number"
ARG_TYPE_JSON="json"
ARG_TYPE_DEFAULT="$ARG_TYPE_STRING"

current_state="$STATE_UNDEFINED"
current_arg_type="$ARG_TYPE_DEFAULT"
actions="[]"

function usage()
{
  echo "Usage:"
  echo "  $0 [--help | --action ACTION_NAME [[FLAGS] ARG_NAME ARG_VALUE...]...]"
}

function print_help()
{
  echo ""
  echo "This tool is a wrapper around jq, to simplify creation of CCF governance proposals."
  echo "Specify a list of actions and associated args. Each arg is assumed to be a string, but"
  echo "you may indicate that any arg should be read as a number (-n) or JSON (-j)."
  echo "Additionally, any @-prefixed string is assumed to be a file path, and will be replaced"
  echo "with the contents of the file."
  args_a=("--action" "set_greeting" "message" "HelloWorld" "-n" "max_repetitions" "42")
  args_b=("--action" "no_arg_action")
  args_c=("--action" "upload_file" "contents" "@file.txt")
  echo ""
  echo "For example:"
  echo "  $0"
  echo "    ${args_a[*]}"
  echo "    ${args_b[*]}"
  echo "    ${args_c[*]}"
  echo ""
  # To keep this help up-to-date, actually run this sample program!
  # But it requires a file, so cheat a little and rewrite that to a temp file
  tmp_file=$(mktemp)
  echo "This is a file." >> $tmp_file
  echo "Containing multiple lines." >> $tmp_file
  args_c[-1]="@$tmp_file"
  echo "Will produce:"
  echo "$($0 ${args_a[@]} ${args_b[@]} ${args_c[@]})"
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
  if [ ! -z "$action" ]; then
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
  if [ "${arg_value:0:1}" == "@" ]; then
    if [[ ! -a "${arg_value:1}" ]]; then
      echo "Could not find file: ${arg_value:1}"
      exit 1
    fi
    arg_value="$(cat "${arg_value:1}")"
  fi
  if [ $current_arg_type == "$ARG_TYPE_NUMBER" ] || [ $current_arg_type == "$ARG_TYPE_JSON" ]; then
    arg_kind="--argjson"
  else
    arg_kind="--arg"
  fi
  action="$(echo "$action" | jq --arg name "$arg_name" $arg_kind value "$arg_value" '.args += {($name): $value}')"
  current_arg_type="$ARG_TYPE_DEFAULT"
}

function consume_flags()
{
  case "$1" in 
    -n)
      current_arg_type="$ARG_TYPE_NUMBER"
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
