A CCF app for implementing Multi-Container execution.

Maintains a node-local set of trusted executors, each running in a distinct attested environment, and dispatches incoming user requests to those executors.

See [here](https://github.com/microsoft/CCF/discussions/4062) for background, and [here](https://github.com/microsoft/CCF/issues?q=is%3Aissue+is%3Aopen+%22Multi-Container%3A%22+in%3Atitle) for implementation plan/remaining issues.

### Expected Flow

```
[Executor]                                                            [CCF Node]

## Executor initialisation

attestation = fetch_attestation()
cert, client_privk = new_key()
supported_endpoints = [
  {"method": "POST", "uri": "/students/{ID}"}
  {"method": "GET", "uri": "/students/{ID}"}
  {"method": "POST", "uri": "/students/{ID}/clone/{ID}"}
]


## Executor registration

make_client(
  ccf_node_address,
  ccf_service_identity,
  anonymous_client_identity
).call(
  "ExecutorRegistration.RegisterExecutor",
  {attestation, cert, supported_endpoints}
)
(Initiate TLS handshake)
                                                       (Allow anonymous, accept)
                                                validate_attestation(attesation)
                                          code_id = get_measurement(attestation)
                             trusted = kv["executor_code_ids"].contains(code_id)
                             accept_executor(code_id, cert, supported_endpoints)
                                             respond({Outcome.ACCEPTED, "LGTM"})


## Executor loop

client = make_client(
  ccf_node_address,
  ccf_service_identity,
  {cert, client_privk}
)
client.call(
  "KV.StartTx"
)
(Initiate TLS handshake)
                                                   (Check cert is known, accept)
                                         check_still_trusted(code_ids[cert], tx)
                                                           active_txs[cert] = tx
                                                   (Lookup request for executor)
                               respond("POST", "/students/Alice/clone/Bob", ...)


## Request execution

(Examine description, exec clone behaviour)
client.call(
  "KV.Get",
  {"public:students", "Alice"}
)
                                                   (Check cert is known, accept)
                                                           tx = active_txs[cert]
                                              ALICE_INFO = tx.ro(table).get(key)
                                                             respond(ALICE_INFO)
client.call(
  "KV.Put",
  {"public:students", "Bob", ALICE_INFO}
)
                                                   (Check cert is known, accept)
                                                           tx = active_txs[cert]
                                                    tx.wo(table).put(key, value)
                                                                       respond()
client.call(
  "KV.EndTx",
  {200, "Cloned Alice successfully"}
)
                                                   (Check cert is known, accept)
                                                           tx = active_txs[cert]
                                                          active_txs.erase(cert)
                                                            result = tx.commit()
                                      (Construct HTTP response, respond to user)
                                                                       respond()
```
