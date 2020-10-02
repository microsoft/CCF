export interface Body<T> {
    text: () => string
    json: () => T
    arrayBuffer: () => ArrayBuffer
}

export interface Request<T=any> {
    headers: { [key: string]: string; }
    params: { [key: string]: string; }
    query: string
    body: Body<T>
}
export interface Response<T=any> {
    statusCode?: number
    headers?: { [key: string]: string; }
    body?: T
}

export interface Table {
    get: (key: string) => string
    put: (key: string, value: string) => void
    remove: (key: string) => void
}

export type Tables = { [key: string]: Table; }

export declare const tables: Tables;
