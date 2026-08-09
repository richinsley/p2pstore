# Architecture and security

## Design goal

p2pstore gives distributed applications a single authoritative object namespace
without sending large objects through NATS or an HTTPS coordination service.
The object API remains streaming end to end, allowing heterogeneous peers to
exchange large datasets or media without buffering complete objects in
application memory.

The central v1 tradeoff is explicit: one named provider is authoritative. This
keeps the catalog and persistence model simple, but availability and durability
are exactly those of that provider and its backup policy.

## Components

```text
Local process                                         Authoritative provider

Application / CLI / S3-compatible client
           |
  127.0.0.1 S3 gateway
           |
     ObjectStore API
           |
   p2pstore.Client ===== QUIC / ICE ===== RPCServer
                                              |
                                        ObjectStore API
                                              |
                                           FSStore
                                              |
                             index.db + blobs/ + tmp/

Control plane: NATS or HTTPS rendezvous -> ICE metadata and TLS pin only
Data plane:    direct QUIC streams        -> RPC headers and object bytes
```

- `ObjectStore` is the boundary shared by local and remote code.
- `FSStore` is the authoritative persistent implementation.
- `Client` is the remote implementation over one established QUIC connection.
- `RPCServer` serves an `ObjectStore` on each accepted QUIC stream.
- `gateway` translates the required local S3 subset to `ObjectStore` calls.
- `natssignal` carries connection metadata and discovers exactly one provider
  through an existing NATS deployment.
- `rendezvous` creates a one-use join capability and transports
  capability-encrypted signaling envelopes over HTTPS long polling.
- `internal/icequic.PacketConn` adapts Pion's connected datagram API to the
  address-aware `net.PacketConn` required by quic-go.

## Peer-session lifecycle

```text
Provider                                      Client / gateway
   |                                                |
   | create signaling session / share capability   |
   |<------------- signaling channel ------------->|
   |                                                |
   | hello: ICE credentials + TLS fingerprint      |
   |<------ trickled UDP ICE candidates ---------->|
   |                                                |
   | ICE controlled             ICE controlling    |
   |<========== selected UDP candidate pair ======>|
   |                                                |
   | QUIC/TLS server             QUIC/TLS client   |
   |<==== TLS 1.3, ALPN, exact certificate pin ===>|
   |                                                |
   |<==== independent bidirectional RPC streams ===>|
```

The provider generates a fresh P-256 ECDSA certificate per session. Its
SHA-256 leaf fingerprint is sent in the provider hello. The client configures
TLS 1.3 with ordinary PKI verification disabled only because an exact
fingerprint comparison replaces it. A missing or mismatched fingerprint fails
the session as unauthenticated; an arbitrary self-signed certificate is never
accepted.

One peer session owns one selected ICE connection, one QUIC connection, the
signaling channel, and (on the provider) a QUIC listener. Closing the session
closes all of them. Reconnection creates a new signaling session, ICE path, and
certificate rather than trying to migrate the existing QUIC connection.

## ICE and QUIC profile

ICE gathers UDP host candidates and, unless `HostOnly` is set, server-reflexive
candidates from configured STUN URLs. It disables mDNS and rejects relayed or
other candidate types received through signaling. TURN and TCP are excluded.

Pion exposes the selected path as a connected `*ice.Conn`, while quic-go expects
`net.PacketConn`. The adapter preserves one-read/one-write datagram boundaries,
delegates deadlines to ICE, always reports the selected peer from `ReadFrom`,
and rejects a `WriteTo` destination that is not that peer. This last rule also
prevents QUIC connection migration.

The v1 QUIC profile allows 128 incoming bidirectional streams, disallows
incoming unidirectional streams, disables 0-RTT and QUIC datagrams, uses a
10-second handshake timeout and two-minute idle timeout, and disables active
path-MTU discovery. Each object operation gets a new bidirectional stream.

## Persistence and crash consistency

FSStore separates immutable body versions from the mutable index:

```text
provider root/
  index.db             bbolt bucket "objects-v1"
  blobs/
    <random>.blob      completed immutable bodies
  tmp/
    put-*.tmp          in-progress bodies only
```

A PUT proceeds in this order:

1. Validate bucket, key, options, and context.
2. Serialize replacement of the same bucket/key.
3. Reserve quota for the object's net growth. Unknown-length bodies grow their
   reservation incrementally while streaming.
4. Stream into `tmp/` through a 64 KiB buffer while hashing SHA-256 and enforcing
   the declared size and context.
5. Sync and close the temporary file.
6. Rename it to a new random immutable name under `blobs/`, then sync that
   directory.
7. Atomically replace the bbolt record.
8. Remove the superseded blob and commit quota accounting.

A failure before step 7 leaves the previous record visible. A failure between
steps 6 and 7 may leave an unreferenced completed blob; startup cleanup removes
it. Cancellation or any validation failure removes the temporary file. Cleanup
also removes expired records/blobs and abandoned `tmp/` entries.

Expiry is enforced on reads and listings, so an expired object behaves as not
found even before the janitor's next one-minute cleanup pass. DELETE remains
idempotent. The index is the namespace source of truth; unreferenced blob files
are garbage, not recoverable object versions.

## Concurrency and memory

- FSStore is safe for concurrent use. Mutations to the same key are serialized;
  independent keys can stream concurrently.
- The quota includes committed bytes and reserved net growth from active PUTs,
  preventing concurrent streams from collectively overshooting `MaxBytes`.
- Object bodies are copied in 64 KiB chunks and are never represented as a
  single object-sized Go buffer.
- A GET body owns its QUIC stream. EOF completes it; closing early resets that
  stream; context cancellation also resets it.
- Canceling `RPCServer.Serve` closes the shared connection because a QUIC stream
  read does not otherwise inherit an arbitrary server context. Serve waits for
  all stream handlers to exit before returning.
- LIST metadata is materialized as JSON, but pages are limited to 1,000 objects
  and clients reject response bodies over 2 MiB.

## Signaling security

### NATS

NATS subjects contain session and peer IDs. The implementation caps signals at
64 KiB and validates the session and sender identity before queueing them. Its
identity and confidentiality are only as strong as the deployment's NATS
authentication, authorization, and TLS configuration. NATS never carries
object bodies in the new transport.

Provider discovery queries all active responders for 250 ms. An explicitly
configured provider must still respond. Without an explicit provider, exactly
one unique, unexpired provider must respond; zero or multiple providers are an
availability error. Random selection is forbidden because it could redirect a
client to a different namespace.

### HTTPS rendezvous

A join code contains the helper URL, a random session ID, provider ID, and a
256-bit capability. The capability is distributed out of band and should be
handled like a short-lived bearer secret.

The peers derive an AES-256-GCM key with HKDF-SHA-256 from the capability and
session ID. Each envelope uses a random nonce and authenticates the session and
sender role as associated data. The helper receives a SHA-256 capability hash
for request authorization and stores only opaque encrypted JSON. Messages are
limited to 64 KiB, sessions live no more than five minutes, a provider listener
can be accepted once, and the helper deletes state after both roles close or
the timer expires.

HTTPS is mandatory except when the parsed host is explicitly loopback. The
exception exists only for local tests; it must not be used across a LAN.

## Trust and excluded threats

Participants authorized by the NATS deployment and holders of a rendezvous join
capability receive full bucket CRUD access. V1 does not authenticate individual
users or objects after the peer session is established.

The authoritative provider is trusted with plaintext object data and metadata.
QUIC encrypts the network path, but FSStore does not encrypt blobs at rest.
Filesystem permissions, full-disk encryption, process isolation, backups, and
provider host security remain operator responsibilities.

STUN improves direct reachability but does not guarantee it. Two symmetric NATs
often require TURN; v1 reports an actionable timeout and stops rather than
quietly placing the data plane on a signaling service.

## Failure behavior

| Failure | Result |
|---|---|
| Provider process or host unavailable | Storage operations fail unavailable until the same provider returns. |
| Ambiguous NATS discovery | Connection fails; no provider is chosen. |
| ICE timeout | Connection fails with guidance that symmetric NAT may require TURN. |
| Certificate pin mismatch | QUIC setup fails unauthenticated. |
| QUIC connection closes | All active streams fail; caller establishes a new peer session. |
| PUT cancellation or length mismatch | No new object becomes visible; old version survives. |
| Quota exhaustion | PUT fails quota exceeded and releases its reservation. |
| Expired object | GET/HEAD behave as not found; LIST omits it. |
| Missing indexed blob | Operation fails internal; the index is inconsistent and requires operator attention. |
