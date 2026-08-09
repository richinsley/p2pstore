# Getting started

This guide shows the two useful library shapes: a local filesystem provider and
a provider/gateway pair connected through the HTTPS rendezvous signaling
implementation. NATS signaling changes only the channel setup; the ICE, QUIC,
RPC, and object-store code is the same.

## Object names and values

Before opening a service, choose names that satisfy the v1 contract:

- Bucket names are 1–63 ASCII letters, digits, `.`, `_`, or `-`, and begin with
  a letter or digit.
- Keys are non-empty UTF-8 strings up to 1,024 bytes. They cannot contain NUL,
  begin with `/`, or contain a path segment equal to `.` or `..`.
- ETags are lowercase hexadecimal SHA-256 hashes of the complete object body.
- List order is lexical byte order by key. A cursor is opaque and is valid only
  with the bucket and prefix that produced it.

## Open a local filesystem provider

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "io"
    "log"

    "github.com/richinsley/p2pstore"
)

func main() {
    cfg := p2pstore.DefaultFSConfig("./p2pstore-data")
    cfg.MaxBytes = 10 << 30

    store, err := p2pstore.OpenFS(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    ctx := context.Background()
    payload := []byte("one independently encoded frame")
    info, err := store.Put(ctx, "media", "frames/000001.hevc",
        bytes.NewReader(payload), p2pstore.PutOptions{
            Size:        int64(len(payload)),
            ContentType: "video/h265",
        })
    if err != nil {
        log.Fatal(err)
    }

    _, body, err := store.Get(ctx, info.Bucket, info.Key)
    if err != nil {
        log.Fatal(err)
    }
    defer body.Close()
    copied, err := io.Copy(io.Discard, body)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("read %d bytes, sha256=%s\n", copied, info.ETag)
}
```

Every successful `Get` transfers ownership of an `io.ReadCloser` to the caller.
Close it even after an early read failure. For a remote client, closing early
resets only the GET stream and releases the server-side file promptly.

## Run the rendezvous helper

For a loopback development test, HTTP is allowed:

```sh
go run ./cmd/p2pstore-rendezvous -listen 127.0.0.1:8443
```

Any non-loopback deployment requires a certificate and key:

```sh
p2pstore-rendezvous \
  -listen 0.0.0.0:8443 \
  -cert /etc/p2pstore/tls/fullchain.pem \
  -key /etc/p2pstore/tls/private-key.pem
```

The helper holds encrypted signaling envelopes in memory for at most five
minutes. It never sees the capability plaintext after request authentication,
cannot decrypt ICE messages, and never receives object bodies.

## Provider flow

The provider owns both durable storage and the short-lived provider peer
session. This example accepts one join capability and one remote peer:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

store, err := p2pstore.OpenFS(p2pstore.DefaultFSConfig("./p2pstore-data"))
if err != nil {
    log.Fatal(err)
}
defer store.Close()

listener, err := rendezvous.NewProviderListener(
    ctx,
    "https://rendezvous.example.org",
    "gpu-provider-1",
    nil,
)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

encodedJoinCode := listener.JoinCode()
fmt.Println("give this secret to exactly one gateway:", encodedJoinCode)

code, err := rendezvous.ParseJoinCode(encodedJoinCode)
if err != nil {
    log.Fatal(err)
}
channel, err := listener.Accept(ctx)
if err != nil {
    log.Fatal(err)
}

iceConfig := p2pstore.DefaultICEConfig(code.SessionID, code.ProviderID)
session, err := p2pstore.AcceptPeer(ctx, channel, iceConfig)
if err != nil {
    log.Fatal(err)
}
defer session.Close()

rpcServer := &p2pstore.RPCServer{Store: store, Logger: log.Default()}
if err := rpcServer.Serve(ctx, session.Conn); err != nil && ctx.Err() == nil {
    log.Fatal(err)
}
```

Set `iceConfig.HostOnly = true` only for CI or same-LAN tests where no
server-reflexive candidates are desired. Normal internet peers should retain
the default STUN URL or provide their own `STUNURLs`.

## Gateway flow

The gateway stores no objects. It dials the provider, wraps the QUIC connection
as an `ObjectStore`, and exposes that remote store to local tools:

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

dialer, err := rendezvous.NewDialer(encodedJoinCode, nil)
if err != nil {
    log.Fatal(err)
}
channel, err := dialer.Dial(ctx, dialer.Code.SessionID)
if err != nil {
    log.Fatal(err)
}

iceConfig := p2pstore.DefaultICEConfig(dialer.Code.SessionID, "mac-gateway-1")
session, err := p2pstore.DialPeer(ctx, channel, iceConfig)
if err != nil {
    log.Fatal(err)
}
defer session.Close()

remote, err := p2pstore.NewClient(session.Conn)
if err != nil {
    log.Fatal(err)
}

s3, err := gateway.NewServer(remote, "127.0.0.1:8333")
if err != nil {
    log.Fatal(err)
}
defer s3.Shutdown(context.Background())

if err := s3.ListenAndServe(); err != nil {
    log.Fatal(err)
}
```

Do not call both `remote.Close` and `session.Close` concurrently; each owns the
same QUIC connection. In an application, choose `session.Close` as the complete
ICE/signaling teardown path, and shut down the HTTP gateway before it.

## S3 compatibility smoke test

With the loopback gateway on port 8333:

```sh
curl -fsS -X PUT \
  -H 'Content-Type: video/webm' \
  --data-binary @video.webm \
  http://127.0.0.1:8333/media/source/video.webm

curl -fsSI \
  http://127.0.0.1:8333/media/source/video.webm

curl -fsS \
  'http://127.0.0.1:8333/media?list-type=2&prefix=source%2F&max-keys=100'
```

For boto3, configure an unsigned, path-style client and use the loopback URL as
`endpoint_url`. Applications can continue to represent object locations as
canonical `s3://bucket/key` URLs while routing HTTP traffic to the local facade.

## Shutdown order

Stop accepting new local HTTP requests before tearing down the peer path:

1. Call `gateway.Server.Shutdown` with a bounded context.
2. Cancel the RPC serving context on a provider.
3. Close the `PeerSession`; this closes QUIC, ICE, and signaling.
4. Close the signaling listener or provider advertisement.
5. Close `FSStore` last, after active RPC handlers have returned.
