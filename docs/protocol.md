# p2pstore protocol v1

This document describes the interoperable behavior implemented by
`ProtocolVersion == 1` and TLS ALPN `p2pstore/1`. The Go types are authoritative
for JSON field names; this document defines stream order and validation rules.

## Transport profile

- ICE candidate types: UDP host and UDP server-reflexive only.
- Default STUN URL: `stun:stun.l.google.com:19302`.
- ICE timeout: 30 seconds unless configured otherwise.
- QUIC handshake timeout: 10 seconds.
- QUIC idle timeout: 2 minutes.
- Maximum peer-initiated bidirectional streams: 128.
- Unidirectional streams, 0-RTT, QUIC datagrams, and migration: disabled.
- One QUIC connection per peer session.
- One peer-initiated bidirectional QUIC stream per RPC operation.

The client/gateway is ICE-controlling and opens the QUIC connection. The
provider is ICE-controlled and accepts it.

## TLS identity

The provider creates a short-lived self-signed P-256 ECDSA certificate for each
session and signals the lowercase hexadecimal SHA-256 digest of its leaf DER.
The client:

1. requires a syntactically valid 32-byte SHA-256 pin;
2. requires TLS 1.3 and ALPN `p2pstore/1`;
3. requires exactly one peer leaf certificate; and
4. compares its SHA-256 digest byte-for-byte with the signaled pin.

There is no fallback to an unpinned self-signed certificate or public-key
infrastructure validation. The signaling channel is therefore part of the
authentication boundary.

## Frame encoding

Each direction begins with one JSON header frame:

```text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|             JSON header length, uint32 big endian             |
+---------------------------------------------------------------+
|                     JSON bytes ...                            |
+---------------------------------------------------------------+
|                 optional operation body ...                   |
+---------------------------------------------------------------+
```

The JSON length must be between 1 and 65,536 bytes. A receiver rejects a larger
length before allocating a body-sized buffer. There is no length prefix around
object data.

### Request header

The conceptual schema is:

```json
{
  "version": 1,
  "operation": "PUT|GET|HEAD|DELETE|LIST|PING",
  "bucket": "bucket-name",
  "key": "path/to/object",
  "body_size": 123,
  "put": {
    "content_type": "video/h265",
    "size": 123,
    "ttl": 0,
    "expires_at": "2026-08-08T12:00:00Z"
  },
  "list": {
    "prefix": "frames/",
    "cursor": "opaque-base64url-value",
    "limit": 1000
  }
}
```

Unused fields are omitted or ignored according to the Go JSON encoding. Go
`time.Duration` values such as `ttl` are encoded as integer nanoseconds.
`expires_at` uses Go's RFC 3339 time encoding.

### Response header

Success:

```json
{
  "version": 1,
  "ok": true,
  "object": {
    "bucket": "bucket-name",
    "key": "path/to/object",
    "size": 123,
    "content_type": "video/h265",
    "etag": "lowercase-sha256-hex",
    "created_at": "2026-08-08T12:00:00Z",
    "expires_at": "2026-08-09T12:00:00Z"
  },
  "body_size": 123
}
```

Failure:

```json
{
  "version": 1,
  "ok": false,
  "error": {
    "code": "invalid_argument",
    "message": "human-readable explanation"
  }
}
```

Every response must use version 1. A failed response must include an error. A
successful response includes only the metadata and body length relevant to its
operation.

## Operations

### PUT

Request header fields: `version`, `operation`, `bucket`, `key`, `body_size`, and
`put`. The server copies `body_size` into `put.size`; conflicting `put.size`
input is not authoritative.

- `body_size >= 0`: exactly that many bytes must follow, followed by stream FIN.
  The receiver probes beyond the boundary once and rejects extra bytes. Too few
  bytes also fail the PUT.
- `body_size == -1`: the body continues until stream FIN and quota is reserved
  incrementally.
- Values below `-1` are invalid.

The client sends FIN after the request body, then reads one response header from
the server's direction. A successful response contains the committed
`object` metadata and no response body. The provider does not publish a partial
or failed version.

### GET

The request consists of a header followed immediately by client stream FIN.
The success response header contains `object` and a non-negative `body_size`,
followed by exactly that many object bytes and server FIN.

The client exposes the body as a streaming `io.ReadCloser`. Reaching the
declared byte count completes the body. EOF before the declared count becomes
`io.ErrUnexpectedEOF`. Closing early or canceling the operation resets the read
side of this stream without canceling unrelated streams.

### HEAD

The request consists of a header and client FIN. The success response contains
`object` and no body.

### DELETE

The request consists of a header and client FIN. The success response contains
no object and no body. Deleting an absent or expired object succeeds, so a
client can retry DELETE safely.

### LIST

The request contains `bucket` and `list`, followed by client FIN. Limit zero
defaults to 1,000; limits below zero or above 1,000 are invalid.

The success response declares `body_size`, followed by a JSON-encoded
`ListResult` and server FIN:

```json
{
  "objects": [],
  "next_cursor": "opaque-base64url-value",
  "truncated": false
}
```

Objects are ordered lexically by key and expired entries are omitted. The
cursor encodes the bucket, prefix, and last key as unpadded base64url JSON, but
clients must treat it as opaque. Reusing it with another bucket or prefix is an
invalid argument. The Go client refuses LIST response bodies above 2 MiB.

### PING

PING has no bucket, key, or body. The server returns a success header. It tests
the ability to open and service a new stream; it does not check filesystem
contents.

## Error codes

| Code | Meaning | Typical HTTP facade status |
|---|---|---:|
| `invalid_argument` | Invalid name, option, frame, version, or body length | 400 |
| `not_found` | Object is absent or expired | 404 |
| `quota_exceeded` | PUT would exceed provider quota | 507 |
| `unavailable` | Signaling, ICE, QUIC, or provider is unavailable | 503 |
| `unauthenticated` | Identity, capability, expiry, or TLS pin rejected | 403 |
| `internal` | Unexpected provider or protocol failure | 500 |

Local `context.Canceled` and `context.DeadlineExceeded` errors remain ordinary
Go context errors. Transport errors observed by the client are wrapped as
`unavailable`. Provider errors are normalized before crossing the wire so an
underlying local filesystem error is never serialized.

Stream cancellation uses application stream error code `0x10`. This value is
an implementation detail for v1 peers, not a storage error code.

## Object validation

Buckets match this shape:

```text
[A-Za-z0-9][A-Za-z0-9._-]{0,62}
```

Keys must be valid UTF-8 and at most 1,024 encoded bytes. Empty keys, NUL,
leading `/`, absolute paths, and path segments exactly equal to `.` or `..` are
invalid. Empty path segments and ordinary dots inside a segment are allowed.

Prefixes must be valid UTF-8, contain no NUL, and be at most 1,024 bytes. A
prefix is not interpreted as a filesystem path.

## Signaling messages

Signals carry connection metadata only:

```json
{
  "protocol_version": 1,
  "type": "hello|candidate|gathering_complete",
  "session_id": "shared-session-id",
  "peer_id": "sender-id",
  "role": "provider|client",
  "ice_ufrag": "hello-only",
  "ice_password": "hello-only",
  "candidate": "candidate-only",
  "expires_at": "2026-08-08T12:05:00Z",
  "tls_fingerprint": "provider-hello-only"
}
```

Each receiver verifies protocol version, session ID, distinct non-empty peer
ID, the opposite role, and a future expiry before acting on a signal. Exactly
one non-empty hello is accepted. Candidate messages must decode as host or
server-reflexive candidates. Gathering completion maps to Pion's nil remote
candidate marker.

Signaling implementations may add transport envelopes, authentication, and
sequence numbers, but must not change the Signal payload or carry object bytes.

## S3 compatibility mapping

The gateway is not part of the peer wire protocol. It maps local, unsigned,
path-style HTTP requests as follows:

| HTTP request | ObjectStore call |
|---|---|
| `PUT /bucket/key` | `Put` |
| `GET /bucket/key` | `Get` |
| `HEAD /bucket/key` | `Head` |
| `DELETE /bucket/key` | `Delete` |
| `GET /bucket?list-type=2` | `List` |

`Content-Type`, `Content-Length`, ETag, last-modified time, prefix, max-keys,
and continuation tokens are translated. AWS signatures, range headers,
conditional headers, multipart, and bucket operations are not implemented.

## Versioning rules

Protocol additions that change frame order, validation, TLS identity, or body
interpretation require a new protocol version and ALPN. Implementations must
reject unknown request or response versions; they must not guess or silently
downgrade. New optional JSON metadata can be added only when old peers can
safely ignore it without changing operation semantics.
