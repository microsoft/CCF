import { ccf } from "../ccf/builtin";
import * as ccfUtil from "../ccf/util";

export namespace kv {
  type User = string;

  interface PollBase<T> {
    creator: string;
    type: string;
    opinions: Record<User, T>;
  }

  interface StringPoll extends PollBase<string> {
    type: "string";
  }

  interface NumericPoll extends PollBase<number> {
    type: "number";
  }

  export type Poll = StringPoll | NumericPoll;

  export type PollMap = ccfUtil.TypedKVMap<string, Poll>;

  export function getPollMap(): PollMap {
    return new ccfUtil.TypedKVMap(ccf.kv.polls, ccfUtil.string, ccfUtil.json<kv.Poll>());
  }
}
