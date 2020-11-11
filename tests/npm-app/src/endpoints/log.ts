import * as ccf from "../types/ccf";

interface LogItem {
  msg: string;
}

interface LogEntry extends LogItem {
  id: number;
}

const logMap = new ccf.TypedKVMap(ccf.kv.log, ccf.uint32, ccf.json<LogItem>());

export function getLogItem(request: ccf.Request): ccf.Response<LogItem> {
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

export function setLogItem(request: ccf.Request<LogItem>): ccf.Response {
  const id = parseInt(request.query.split("=")[1]);
  logMap.set(id, request.body.json());
  return {};
}

export function getAllLogItems(
  request: ccf.Request
): ccf.Response<Array<LogEntry>> {
  let items: Array<LogEntry> = [];
  logMap.forEach(function (item, id, table) {
    items.push({ id: id, msg: item.msg });
  });
  return {
    body: items,
  };
}
