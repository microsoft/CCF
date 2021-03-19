import * as ccfapp from "ccf-app";

interface LogItem {
  msg: string;
}

interface LogEntry extends LogItem {
  id: number;
}

const logMap = new ccfapp.TypedKVMap(
  ccfapp.ccf.kv.log,
  ccfapp.uint32,
  ccfapp.json<LogItem>()
);

export function getLogItem(request: ccfapp.Request): ccfapp.Response<LogItem> {
  const id = parseInt(request.query.split("=")[1]);
  if (!logMap.has(id)) {
    return {
      statusCode: 404,
    };
  }
  return {
    body: logMap.get(id),
  };
}

export function setLogItem(request: ccfapp.Request<LogItem>): ccfapp.Response {
  const id = parseInt(request.query.split("=")[1]);
  logMap.set(id, request.body.json());
  return {};
}

export function getAllLogItems(request: ccfapp.Request): ccfapp.Response<Array<LogEntry>> {
  let items: Array<LogEntry> = [];
  logMap.forEach(function (item, id, table) {
    items.push({ id: id, msg: item.msg });
  });
  return {
    body: items,
  };
}
