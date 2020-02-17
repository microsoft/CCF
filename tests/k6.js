import http from "k6/http";
import { check } from "k6";

export let options = {
  insecureSkipTLSVerify: true,
  tlsAuth: [
    { domains: [`${__ENV.HOST}`],
      cert: open(`${__ENV.USER_CERT}`),
      key: open(`${__ENV.USER_KEY}`) }
  ]
};

const baseURL = `https://${__ENV.HOST}/`;

export function setup()
{
  const body = JSON.stringify({
    jsonrpc: "2.0",
    method: "users/LOG_record",
    params: {
      id: 0,
      msg: "Unique message: d41d8cd98f00b204e9800998ecf8427e"
    }
  });
  const params = {headers: { "Content-Type": "application/json" }}; 

  return {
    body: body,
    params: params
  }
}

export default function(data) {
  var r = http.post(baseURL + "users/LOG_record", data.body, data.params);

  check(r, {
    "status is 200": (r) => r.status === 200
  });
};
