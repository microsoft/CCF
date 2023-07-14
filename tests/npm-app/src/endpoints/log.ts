import * as ccfapp from "@microsoft/ccf-app";

type LogContent = string;

interface LogItem {
  msg: LogContent;
}

interface LogEntry extends LogItem {
  id: number;
}

interface LogVersion {
  id: number;
  version: number;
}

const logMap = ccfapp.typedKv("log", ccfapp.uint32, ccfapp.json<LogContent>());

export function getLogItem(request: ccfapp.Request): ccfapp.Response<LogEntry> {
  const id = parseInt(request.query.split("=")[1]);
  if (!logMap.has(id)) {
    return {
      statusCode: 404,
    };
  }
  return {
    body: { id: id, msg: logMap.get(id) },
  };
}
export function getLogItemVersion(
  request: ccfapp.Request,
): ccfapp.Response<LogVersion> {
  const id = parseInt(request.query.split("=")[1]);
  if (!logMap.has(id)) {
    return {
      statusCode: 404,
    };
  }
  return {
    body: { id: id, version: logMap.getVersionOfPreviousWrite(id) },
  };
}

export function setLogItem(request: ccfapp.Request<LogItem>): ccfapp.Response {
  const id = parseInt(request.query.split("=")[1]);
  logMap.set(id, request.body.json().msg);
  return {};
}

export function getAllLogItems(
  request: ccfapp.Request
): ccfapp.Response<Array<LogEntry>> {
  let items: Array<LogEntry> = [];
  logMap.forEach(function (item, id) {
    items.push({ id: id, msg: item });
  });
  return {
    body: items,
  };
}
