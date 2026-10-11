# PAM Protocol

Shared Go wire contracts for PAM Gateway and Kitex RPC services.

The module owns only cross-process metadata keys, identity/request metadata
encoding, and the versioned RPC backward-metadata envelope used to control safe
HTTP response status, headers, cookies, and body omission. It is not a runtime
service and contains no routing, authentication, or observability policy.

See [PAM Gateway and RPC bidirectional protocol](docs/gateway-rpc-protocol.md)
for the background, request/response flows, integration points, and trust
boundaries.

## HTTP conversion scope

PAM uses Kitex `HTTPThriftGeneric` as a constrained BAM-compatible subset:

- one of `api.get/post/put/patch/delete` per public method;
- `api.path`, `api.query`, `api.body`, `api.form`, `api.none`, and
  `api.js_conv`;
- multipart file parts mapped to `binary (api.form = "...")`;
- `api.http_code` and safe response fields, with status/header/cookie overrides
  carried by `x-pam-http-response`.

PAM does not promise full AGW compatibility. Raw browser Cookie/Authorization,
arbitrary headers, implicit parameter-source fallback, multiple routes per
method, Base/BaseResp conventions, streaming, and response `api.raw_body` are
outside the current contract.

## Trust boundary

Values received from a public HTTP request are untrusted. PAM Gateway removes
all public `x-pam-*` headers and creates trusted identity metadata only after
Auth RPC verification. RPC services must not derive authorization from raw HTTP
Cookie or Authorization headers.

## Backward response metadata

Kitex backward metadata key `x-pam-http-response` contains a versioned JSON
object with optional HTTP status, allowlisted multi-value headers, cookie
mutations, and RFC 6901 body omission paths. Multiple cookies are represented as
an array because Kitex metainfo stores one string per key. Producers call
`httpmeta.Send`; PAM Gateway calls `httpmeta.Receive` and applies the result only
after full validation.
