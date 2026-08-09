# Operations and testing

## Provider storage layout

Configure a dedicated provider directory, for example:

```text
/srv/p2pstore/data/
  index.db
  blobs/
  tmp/
```

`OpenFS` creates directories with mode `0700`, the bbolt database with mode
`0600`, and waits up to one second for the database lock. Only one provider
process may open a directory at once. Existing parent-directory permissions and
the process umask still matter; run the provider as a dedicated account and do
not expose this directory through a web server.

Store p2pstore data in a dedicated directory, not inside or over unrelated
application, database, or JetStream state. Backend switching does not move or
reinterpret existing files.

### Capacity and expiry

- `MaxBytes == 0` means no application quota. Set a quota below filesystem
  capacity so temporary system files, the index, and operational headroom do
  not compete with object blobs.
- Quota accounting covers committed body sizes and reservations for active
  PUTs. Metadata and filesystem allocation overhead are not included.
- `DefaultTTL == 0` means objects do not expire unless a PUT supplies a TTL or
  absolute expiry.
- The janitor defaults to one minute. Reads enforce expiry immediately; the
  interval controls physical space reclamation, not visibility.

Monitor both p2pstore quota failures and actual free disk space. A zero or very
large `MaxBytes` does not protect the provider from filesystem exhaustion.

## Backup and restore

The provider is the only authoritative copy in v1. Back it up accordingly.

The simplest consistent backup procedure is:

1. Stop local gateways from starting new operations.
2. Cancel and close active peer sessions and wait for RPC serving to return.
3. Close `FSStore`.
4. Snapshot or copy the complete provider root, including `index.db` and
   `blobs/`, as one unit. `tmp/` is not required for recovery.
5. Reopen the provider and resume sessions.

For online backups, use a filesystem snapshot that captures the database and
blob directory at the same instant. Copying a live bbolt file separately from
live blobs can capture an index/blob mismatch and is not a supported backup.

To restore, keep the provider stopped, restore the entire root to a private
directory on the same filesystem, verify ownership and free space, then call
`OpenFS`. Startup removes expired records, temporary files, and unreferenced
blobs. It does not recreate a missing blob referenced by the index.

Test restoration regularly by opening a copy and verifying representative
objects' sizes and SHA-256 ETags.

## Rendezvous helper

Build the helper:

```sh
go build -o p2pstore-rendezvous ./cmd/p2pstore-rendezvous
```

Development loopback service:

```sh
./p2pstore-rendezvous -listen 127.0.0.1:8443
```

Network service with TLS:

```sh
./p2pstore-rendezvous \
  -listen 0.0.0.0:8443 \
  -cert /etc/p2pstore/tls/fullchain.pem \
  -key /etc/p2pstore/tls/private-key.pem
```

The command refuses a non-loopback bind without both certificate files. Place
it behind ordinary process supervision. It is deliberately in-memory: restart
invalidates outstanding join codes, and peers should create a fresh session.

Expose only the helper's HTTPS port. The object provider and local S3 gateways
do not need public TCP listeners. ICE needs outbound and return UDP permitted by
the host and network firewalls.

The current in-memory helper is suitable for a user-hosted, low-volume
coordination service. It does not implement distributed state, persistent
queues, multi-instance routing, or general account management.

## NATS signaling

Use authenticated NATS with TLS for traffic crossing untrusted networks. Peer
and session IDs become subject tokens and therefore cannot contain `.`, `*`,
`>`, spaces, or be empty.

The provider owns three lifetimes:

- the discovery subscription returned by `AnnounceProvider`;
- the `natssignal.Listener` that accepts peer sessions; and
- each accepted `SignalChannel`, later owned by `PeerSession`.

Unsubscribe the advertisement immediately if the node stops being the
authoritative provider. Close the listener on shutdown or role transition. A
client with an explicit provider ID still requires that exact provider to
advertise; this prevents silently connecting to a stale or different namespace.

## Observability

Set `RPCServer.Logger` to receive one line after every handled stream:

```text
operation=PUT bucket="media" key="frames/000001.hevc" bytes=82142 duration=12.4ms error=<nil>
```

Collect at least:

- count, bytes, latency, and error code by operation;
- current provider identity and peer-session reconnect count;
- ICE negotiation time and selected candidate types (without credentials);
- quota failures, filesystem free space, and provider root size;
- janitor or startup cleanup errors;
- open file descriptors and process heap during large concurrent transfers;
- rendezvous session create/reject/expire counts without logging capabilities
  or encrypted envelope bodies.

Never log ICE passwords, join codes, capabilities, HTTP authorization hashes,
private keys, or full signaling envelopes. Object keys may also contain
sensitive project names; deployments should decide whether to redact them.

## Troubleshooting

### `ICE negotiation timed out; symmetric NAT may require TURN`

1. Confirm the peers used the same session ID, different peer IDs, and opposite
   roles.
2. Verify clocks are close enough that five-minute signaling messages have not
   expired.
3. Verify each peer can resolve and reach its configured STUN server over UDP.
4. Check host firewalls and container/network policies for UDP restrictions.
5. Test `HostOnly` on the same LAN. If LAN works but two internet networks do
   not, inspect NAT type.
6. If either side uses symmetric NAT, v1 may not connect. TURN is required but
   intentionally not implemented; do not tunnel object bodies through NATS or
   rendezvous as an ad hoc fallback.

### TLS fingerprint mismatch

Treat this as an authentication failure, not a retryable certificate warning.
Discard the join code/session and create a new one. Confirm the signaling
channel is authenticated and that provider/client roles were not mixed between
two concurrent sessions.

### Ambiguous provider discovery

More than one NATS member advertised itself as authoritative. Stop the incorrect
advertisement or configure the intended `provider_node`. Do not choose one at
random; the providers may contain unrelated namespaces.

### Indexed blob is missing

The metadata index points to a body file that is absent. Stop writes, preserve
the provider root for diagnosis, inspect storage and backup logs, and restore a
consistent snapshot. Startup cleanup cannot reconstruct the missing content.

### Quota exceeded with apparent free space

`MaxBytes` is independent of filesystem capacity and includes reservations by
active PUTs. Wait for failed/canceled PUTs to return and release reservations,
or increase the configured quota after confirming real disk headroom.

## Routine verification

Run formatting, static analysis, unit/integration tests, and the race detector:

```sh
gofmt -w .
go vet ./...
staticcheck ./...
go test ./...
go test -race ./...
```

Socket-dependent tests bind loopback TCP and UDP ports. They require an
execution environment that permits local listeners. The NATS tests start an
embedded server; rendezvous tests use `httptest`; ICE and QUIC tests bind UDP.

Fuzz the bounded JSON framing parser:

```sh
go test ./internal/wire -fuzz=FuzzReadHeader -fuzztime=30s
```

Run the opt-in large streaming acceptance suite on a machine with at least 2
GiB of temporary disk headroom:

```sh
P2PSTORE_LARGE_TESTS=1 go test -run TestLargeStreamingAcceptance -v
```

It performs a 1 GiB PUT and GET with SHA-256 verification, then eight concurrent
64 MiB PUT/GET pairs. The endpoints share one test process, so heap thresholds
are aggregate: 128 MiB for the single transfer and 512 MiB for the concurrent
case.

## Transport feasibility gate

The ICE-to-QUIC adapter gate is not an optional unit test. It must stay green
before integration rollout:

```sh
go test ./internal/icequic -run TestICEQUICTransportGate -v
```

The gate covers:

- ICE connection establishment and selected remote addresses;
- preservation of datagram boundaries;
- read/write deadlines and cancellation;
- MTU-sized (1,280-byte) traffic;
- TLS/QUIC handshake and ALPN;
- rejection of the wrong certificate pin;
- eight simultaneous bidirectional streams without corruption; and
- clean connection shutdown.

If this gate fails on a supported platform, stop transport rollout and diagnose
the adapter or dependency behavior. Substituting an unreviewed transport changes
the security and streaming architecture.

## Real-network acceptance

CI host-only ICE does not prove internet reachability. Before a release or
network change, test from two independently routed networks using configured
STUN servers:

1. Establish the provider and gateway through the production signaling path.
2. Record selected candidate types without recording credentials.
3. PUT and GET a generated large object and compare size and SHA-256.
4. Run eight concurrent transfers and check heap, file descriptors, throughput,
   and absence of cross-stream blocking.
5. Cancel an in-progress PUT and confirm no object or persistent temporary blob.
6. Cancel/close an in-progress GET and confirm prompt stream and file release.
7. Restart the provider and verify committed objects, lexical pagination, TTL,
   quota accounting, and orphan cleanup.
8. Stop the provider and confirm clients report unavailable without promoting
   or redirecting to another namespace.
9. Verify signaling logs and captures contain no object body bytes.

For application-level acceptance, send all object operations to a storage-less
gateway, import a representative real-world dataset, and read it back through
the same QUIC path. Verify that application-facing URLs, metadata, pagination,
and streaming behavior remain stable across local and remote ObjectStore
implementations.

## Legacy cutover

Do not dual-write or automatically migrate. A manual copy is intentionally
explicit:

1. Select the legacy backend.
2. Enumerate and GET each old object.
3. Select P2P and PUT each object, preserving content type and desired expiry.
4. Verify size and hash in the provider namespace.
5. Retain the old data for the rollback window.

Rollback selects the old backend and therefore exposes only objects written to
that backend. Document the cutover time so operators understand why newer P2P
objects are absent after rollback.
