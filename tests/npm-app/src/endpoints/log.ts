import * as ccf from '../types/ccf'

interface LogItem {
    msg: string
}

const logMap = new ccf.TypedKVMap(ccf.kv.log, ccf.uint32, ccf.json<LogItem>());

export function getLogItem(request: ccf.Request): ccf.Response<LogItem> {
    const id = parseInt(request.query.split('=')[1])
    if (!logMap.has(id)) {
        return {
            statusCode: 404
        }
    }
    return {
        body: logMap.get(id)
    }
}

export function setLogItem(request: ccf.Request<LogItem>): ccf.Response {
    const id = parseInt(request.query.split('=')[1])
    logMap.set(id, request.body.json());
    return {};
}
