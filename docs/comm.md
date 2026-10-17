# Application connections over ICE/QUIC

`AcceptComm` and `DialComm` reuse p2pstore's signaling, ICE candidate selection,
certificate fingerprint pinning, and QUIC handshake without starting the object
RPC. They negotiate `p2pstore-comm/1` rather than `p2pstore/1`. Each
`CommSession.OpenConn` or `AcceptConn` yields one independent bidirectional
`net.Conn` backed by a QUIC stream. Both peers can open streams. Closing a
stream leaves the session and its other streams alive; closing the session
releases the QUIC connection, ICE agent, and signaling channel.

The caller supplies the signaling channel and `ICEConfig`. For example, an
application can mount the existing rendezvous handler in its own HTTPS server:

```go
handler := rendezvous.NewServer()
mux.Handle("/connect/", http.StripPrefix("/connect", handler))
// Serve mux using the application's HTTPS server and access policy.
```

The provider creates one short-lived rendezvous session and distributes the
join code through its own control plane:

```go
listener, err := rendezvous.NewProviderListener(ctx, "https://example.com/connect", "provider-id", nil)
if err != nil { return err }
defer listener.Close()
code, err := rendezvous.ParseJoinCode(listener.JoinCode())
if err != nil { return err }
signal, err := listener.Accept(ctx)
if err != nil { return err }
cfg := p2pstore.DefaultICEConfig(code.SessionID, code.ProviderID)
comm, err := p2pstore.AcceptComm(ctx, signal, cfg)
if err != nil { return err }
defer comm.Close()
conn, err := comm.AcceptConn(ctx)
if err != nil { return err }
defer conn.Close()
// Hand conn to the application's byte-stream protocol.
```

The joining peer parses that code, obtains the other signaling channel, and
calls `DialComm` with the same session ID and a distinct peer ID. It then calls
`OpenConn`. `signal/rendezvous` is only one adapter; another `SignalChannel`
implementation can be used without changing the comm API. The helper's URL
can be hosted by a portal, an existing application server, or a small
standalone service. It is not a required p2pstore service.

This API does **not** supply a reusable `net.Listener`, durable discovery,
reconnection, TURN fallback, or application authentication. The join code is
a short-lived bearer capability for one session; its holder can participate
in that session. A mesh or other application must bind the resulting connection
to its own peer identity and authorization before accepting protocol traffic.
The HTTP helper requires HTTPS except on explicit loopback addresses.
The current in-memory helper limits each envelope and session lifetime but
does not bound the total number of sessions or queued envelopes; an operator
should not expose it to arbitrary unauthenticated traffic without front-end
limits or further hardening.
