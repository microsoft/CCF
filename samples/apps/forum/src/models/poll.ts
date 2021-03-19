import * as ccfapp from "ccf-app";

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

  export type PollMap = ccfapp.TypedKVMap<string, Poll>;

  export function getPollMap(): PollMap {
    return new ccfapp.TypedKVMap(
      ccfapp.ccf.kv.polls,
      ccfapp.string,
      ccfapp.json<kv.Poll>()
    );
  }
}
