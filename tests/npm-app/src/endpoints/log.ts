import * as ccf from '../types/ccf'

interface LogItem {
    msg: string
}

const logMap = new ccf.TypedKVMap(ccf.kv.log, ccf.uint32, ccf.string);

export function getLogItem(request: ccf.Request): ccf.Response<LogItem> {
    const id = parseInt(request.query.split('=')[1])
    return {
        body: {
            msg: logMap.get(id)
        }
    }
}

export function setLogItem(request: ccf.Request<LogItem>): ccf.Response {
    const id = parseInt(request.query.split('=')[1])
    const body = request.body.json();
    logMap.set(id, body.msg);
    return {};
}
