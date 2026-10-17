# p2pstore

`github.com/richinsley/p2pstore` is a streaming object store for direct
peer-to-peer storage access. One authoritative provider owns the object
namespace; clients reach it through QUIC streams over an ICE-selected UDP path.
Signaling is used only to discover and connect peers—object bytes never cross
NATS or the HTTPS rendezvous helper.

```text
Application / CLI / S3-compatible client
                    |
          loopback S3 compatibility API
                    |
             p2pstore.Client
                    |
       concurrent QUIC streams over ICE
                    |
             p2pstore.RPCServer
                    |
        FSStore blobs + bbolt metadata
```

## Status and scope

The v1 implementation includes:

- streaming `PUT`, `GET`, `HEAD`, `DELETE`, and lexical, paginated `LIST`;
- filesystem blob versions plus a bbolt index, atomic replacement, startup
  recovery, SHA-256 ETags, expiry, and byte quotas;
- one QUIC connection per peer session and one bidirectional stream per
  operation, using ALPN `p2pstore/1`;
- UDP host and server-reflexive ICE candidates with configurable STUN;
- short-lived ECDSA provider certificates pinned to a fingerprint carried by
  authenticated signaling;
- optional NATS signaling and unambiguous provider discovery;
- optional capability-encrypted HTTPS rendezvous signaling;
- an unsigned, path-style S3 compatibility gateway for local applications and
  S3-compatible clients.

Version 1 intentionally does **not** provide replication, automatic provider
failover, TURN relay, TCP ICE candidates, QUIC migration, per-user ACLs,
multipart upload, range GET, conditional requests, version-listing, bucket
administration, or AWS request authentication.

The authoritative provider is the durable copy. If it is unavailable, storage
is unavailable; another node must not silently create an empty replacement
namespace.

## Install

The module requires Go 1.25 or newer.

```sh
go get github.com/richinsley/p2pstore
```

Transport and persistence dependencies are pinned in `go.mod`, including Pion
ICE v4.4.1, quic-go v0.61.0, and bbolt v1.4.3.

## Minimal local provider

An `FSStore` can be used directly through the `ObjectStore` interface:

```go
cfg := p2pstore.DefaultFSConfig("./data/p2pstore")
cfg.DefaultTTL = 24 * time.Hour // optional; zero means no default expiry
cfg.MaxBytes = 100 << 30        // optional; zero means unlimited

store, err := p2pstore.OpenFS(cfg)
if err != nil {
    log.Fatal(err)
}
defer store.Close()

info, err := store.Put(
    context.Background(),
    "media",
    "frames/000001.hevc",
    input,
    p2pstore.PutOptions{
        Size:        inputSize,
        ContentType: "video/h265",
    },
)
```

To expose that store to path-style S3 clients on loopback:

```go
server, err := gateway.NewServer(store, "127.0.0.1:9800")
if err != nil {
    log.Fatal(err)
}
defer server.Shutdown(context.Background())
log.Fatal(server.ListenAndServe())
```

The HTTP endpoint supports unsigned `PutObject`, `GetObject`, `HeadObject`,
`DeleteObject`, and paginated `ListObjectsV2`. It is a local compatibility API,
not the peer-to-peer storage protocol and not a general S3 server.

## Remote sessions

A remote deployment has two independent phases:

1. A signaling implementation supplies matching `SignalChannel` values. Use
   `signal/natssignal` with an existing NATS deployment or `signal/rendezvous`
   with an out-of-band join capability.
2. The provider calls `AcceptPeer` and serves the resulting connection with
   `RPCServer`. The gateway calls `DialPeer`, creates a `Client`, and optionally
   exposes it with `gateway.Server`.

Both roles must use the same session ID and distinct peer IDs. See
[Getting started](docs/getting-started.md) for complete provider/client flows.

## Application connections over ICE/QUIC

Applications that do not speak the object RPC can use `AcceptComm` and
`DialComm` with the same signaling channels. A `CommSession` opens or accepts
independent bidirectional `net.Conn` streams under the separate
`p2pstore-comm/1` ALPN. This is a connection primitive, not a NATS transport or
an authenticated mesh membership protocol. The HTTP rendezvous handler can be
mounted in an application-owned server; no particular portal is required.
See [Application connections](docs/comm.md) for the API, lifecycle, and trust
boundary.

## Documentation

- [Getting started](docs/getting-started.md): local API, remote rendezvous
  provider and gateway, S3 smoke test, and shutdown order.
- [Application connections](docs/comm.md): stream-based `net.Conn` API and
  application-owned HTTPS rendezvous mounting.
- [Architecture and security](docs/architecture.md): components, control/data
  planes, persistence, concurrency, trust, and failure behavior.
- [Protocol v1](docs/protocol.md): ICE/QUIC profile, TLS pinning, frames,
  operation bodies, errors, signaling messages, and compatibility rules.
- [Operations and testing](docs/operations.md): storage layout, backup/restore,
  rendezvous deployment, observability, troubleshooting, test commands, and
  acceptance criteria.

Package GoDoc is the source of truth for individual Go symbols:

```sh
go doc github.com/richinsley/p2pstore
go doc github.com/richinsley/p2pstore/gateway
go doc github.com/richinsley/p2pstore/signal/rendezvous
```

## Verification

```sh
go test ./...
go test -race ./...
go test ./internal/wire -fuzz=FuzzReadHeader -fuzztime=30s
P2PSTORE_LARGE_TESTS=1 go test -run TestLargeStreamingAcceptance -v
```

The large acceptance suite writes about 1.5 GiB of temporary data. Automated
host-only ICE tests prove the Pion-to-`net.PacketConn` adapter, QUIC handshake,
packet boundaries, deadlines, cancellation, ALPN, and concurrent streams. Real
NAT acceptance still requires two independently routed networks. Symmetric NAT
failure is expected to say that TURN is required; v1 never silently relays data.

## Existing data and rollback

Integrations retain explicit legacy backend switches during rollout. There is
no dual write and no automatic migration. Copy objects by reading each object
from the selected old backend and writing it to P2P. Selecting the old backend
again exposes only objects stored there; it does not include later P2P writes.
