This folder implements the governance API exposed under the `/gov` prefix.

The API implemented by the running CCF build is selected by omitting the
`api-version` query parameter or by passing `api-version=latest`. Its OpenAPI
document is generated from the endpoint registrations and returned by
`GET /gov/api`. `latest` is a moving alias and is not a compatibility pin.

Older, dated API versions may also be accepted while they remain supported.
`GET /gov/api?api-version=<dated-version>` returns the frozen OpenAPI document
for that version.

Implementation notes:

- Endpoint registrations must describe their request and response types so the
  generated `latest` document remains accurate.
- All endpoints validate a supplied `api-version`. An omitted version selects
  `latest`.
- The frontend implementation is split into components for acknowledgements,
  proposals, recovery, service state, and transactions.
