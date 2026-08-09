// Package p2pstore provides a streaming object store whose authoritative
// provider can be reached over QUIC streams negotiated through ICE.
//
// The package separates the data plane from the signaling plane. A
// SignalChannel exchanges short-lived ICE credentials, candidates, peer
// identity, and a TLS certificate fingerprint. Once ICE selects a UDP path,
// QUIC carries object requests and bodies directly between the peers; object
// bytes never pass through signaling.
//
// A typical provider opens an [FSStore], accepts a signaling channel with
// [AcceptPeer], and passes the resulting QUIC connection to [RPCServer.Serve].
// A client obtains the matching signaling channel, calls [DialPeer], wraps the
// connection with [NewClient], and then uses the returned [Client] through the
// [ObjectStore] interface. The gateway subpackage can expose any ObjectStore as
// a small, loopback S3-compatible API for local applications.
//
// Version 1 deliberately has one authoritative provider and no replication,
// failover, TURN relay, connection migration, access-control list, or multipart
// upload support. See the repository README and docs directory for deployment,
// protocol, security, and operational details.
package p2pstore
