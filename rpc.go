package p2pstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/richinsley/p2pstore/internal/wire"
)

// ProtocolVersion is the JSON header protocol spoken over ALPN p2pstore/1.
const ProtocolVersion = 1

const (
	opPut    = "PUT"
	opGet    = "GET"
	opHead   = "HEAD"
	opDelete = "DELETE"
	opList   = "LIST"
	opPing   = "PING"
)

// streamCanceled is the application stream-reset code used for canceled or
// abandoned operations. It is not exposed as a storage error code.
const streamCanceled quic.StreamErrorCode = 0x10

// maxListBodySize independently bounds the one RPC response body that is
// intentionally materialized in memory.
const maxListBodySize = 2 * 1024 * 1024

// rpcRequest is the single JSON header that starts the client-to-provider
// direction of every operation stream.
type rpcRequest struct {
	Version   int         `json:"version"`
	Operation string      `json:"operation"`
	Bucket    string      `json:"bucket,omitempty"`
	Key       string      `json:"key,omitempty"`
	BodySize  int64       `json:"body_size,omitempty"`
	Put       PutOptions  `json:"put,omitempty"`
	List      ListOptions `json:"list,omitempty"`
}

// rpcResponse is the single JSON header that starts the provider-to-client
// direction. An optional body follows for GET and LIST only.
type rpcResponse struct {
	Version  int         `json:"version"`
	OK       bool        `json:"ok"`
	Error    *Error      `json:"error,omitempty"`
	Object   *ObjectInfo `json:"object,omitempty"`
	BodySize int64       `json:"body_size,omitempty"`
}

// Client implements ObjectStore over one established QUIC peer session. Each
// operation uses a new bidirectional QUIC stream, so calls may run concurrently
// without serializing object bodies behind one another.
type Client struct {
	conn *quic.Conn
}

var _ ObjectStore = (*Client)(nil)

// NewClient wraps an established, fingerprint-pinned p2pstore QUIC connection.
// The caller transfers connection shutdown responsibility to the Client.
func NewClient(conn *quic.Conn) (*Client, error) {
	if conn == nil {
		return nil, errorf(CodeInvalidArgument, "nil QUIC connection")
	}
	return &Client{conn: conn}, nil
}

// Close closes the shared QUIC connection and interrupts all active operations.
func (c *Client) Close() error {
	return c.conn.CloseWithError(0, "client closed")
}

// Put streams body to the remote provider on a new QUIC stream. If Size is
// positive, both endpoints verify that the body length matches it.
func (c *Client) Put(ctx context.Context, bucket, key string, body io.Reader, options PutOptions) (ObjectInfo, error) {
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, err
	}
	if body == nil {
		return ObjectInfo{}, errorf(CodeInvalidArgument, "PUT body is nil")
	}
	bodySize := options.Size
	if bodySize == 0 {
		bodySize = -1
	}
	stream, err := c.open(ctx)
	if err != nil {
		return ObjectInfo{}, err
	}
	defer stream.CancelRead(streamCanceled)
	request := rpcRequest{Version: ProtocolVersion, Operation: opPut, Bucket: bucket, Key: key, BodySize: bodySize, Put: options}
	request.Put.Size = bodySize
	if err = wire.WriteHeader(stream, request); err != nil {
		stream.CancelWrite(streamCanceled)
		return ObjectInfo{}, unavailable(err)
	}
	written, err := copyContext(ctx, stream, body)
	if err != nil {
		stream.CancelWrite(streamCanceled)
		return ObjectInfo{}, err
	}
	if bodySize >= 0 && written != bodySize {
		stream.CancelWrite(streamCanceled)
		return ObjectInfo{}, errorf(CodeInvalidArgument, "PUT body size %d does not match declared size %d", written, bodySize)
	}
	if err = stream.Close(); err != nil {
		return ObjectInfo{}, unavailable(err)
	}
	response, err := readResponse(stream)
	if err != nil {
		return ObjectInfo{}, err
	}
	if response.Object == nil {
		return ObjectInfo{}, errorf(CodeInternal, "PUT response omitted object metadata")
	}
	return *response.Object, nil
}

// Get starts a remote GET and returns after receiving metadata, without
// buffering the body. Closing the body early cancels only this QUIC stream.
func (c *Client) Get(ctx context.Context, bucket, key string) (ObjectInfo, io.ReadCloser, error) {
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, nil, err
	}
	stream, err := c.open(ctx)
	if err != nil {
		return ObjectInfo{}, nil, err
	}
	if err = wire.WriteHeader(stream, rpcRequest{Version: ProtocolVersion, Operation: opGet, Bucket: bucket, Key: key}); err != nil {
		stream.CancelRead(streamCanceled)
		stream.CancelWrite(streamCanceled)
		return ObjectInfo{}, nil, unavailable(err)
	}
	if err = stream.Close(); err != nil {
		stream.CancelRead(streamCanceled)
		return ObjectInfo{}, nil, unavailable(err)
	}
	response, err := readResponse(stream)
	if err != nil {
		stream.CancelRead(streamCanceled)
		return ObjectInfo{}, nil, err
	}
	if response.Object == nil || response.BodySize < 0 {
		stream.CancelRead(streamCanceled)
		return ObjectInfo{}, nil, errorf(CodeInternal, "GET response omitted body metadata")
	}
	body := newRemoteBody(ctx, stream, response.BodySize)
	return *response.Object, body, nil
}

// Head returns remote object metadata without transferring its body.
func (c *Client) Head(ctx context.Context, bucket, key string) (ObjectInfo, error) {
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, err
	}
	response, err := c.noBody(ctx, rpcRequest{Version: ProtocolVersion, Operation: opHead, Bucket: bucket, Key: key})
	if err != nil {
		return ObjectInfo{}, err
	}
	if response.Object == nil {
		return ObjectInfo{}, errorf(CodeInternal, "HEAD response omitted object metadata")
	}
	return *response.Object, nil
}

// Delete idempotently removes a remote object.
func (c *Client) Delete(ctx context.Context, bucket, key string) error {
	if err := validateObject(bucket, key); err != nil {
		return err
	}
	_, err := c.noBody(ctx, rpcRequest{Version: ProtocolVersion, Operation: opDelete, Bucket: bucket, Key: key})
	return err
}

// List returns one lexical metadata page from the remote provider. LIST bodies
// are bounded to 2 MiB in addition to the 1,000-object page limit.
func (c *Client) List(ctx context.Context, bucket string, options ListOptions) (ListResult, error) {
	if err := validateBucket(bucket); err != nil {
		return ListResult{}, err
	}
	options, err := normalizeListOptions(options)
	if err != nil {
		return ListResult{}, err
	}
	stream, err := c.open(ctx)
	if err != nil {
		return ListResult{}, err
	}
	defer stream.CancelRead(streamCanceled)
	if err = wire.WriteHeader(stream, rpcRequest{Version: ProtocolVersion, Operation: opList, Bucket: bucket, List: options}); err != nil {
		stream.CancelWrite(streamCanceled)
		return ListResult{}, unavailable(err)
	}
	if err = stream.Close(); err != nil {
		return ListResult{}, unavailable(err)
	}
	response, err := readResponse(stream)
	if err != nil {
		return ListResult{}, err
	}
	if response.BodySize < 0 || response.BodySize > maxListBodySize {
		return ListResult{}, errorf(CodeInternal, "invalid LIST response body size")
	}
	body := make([]byte, response.BodySize)
	if _, err = io.ReadFull(stream, body); err != nil {
		return ListResult{}, unavailable(err)
	}
	var result ListResult
	if err = json.Unmarshal(body, &result); err != nil {
		return ListResult{}, errorf(CodeInternal, "decode LIST response: %v", err)
	}
	return result, nil
}

// Ping verifies that the remote RPC server can accept and answer a new stream.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.noBody(ctx, rpcRequest{Version: ProtocolVersion, Operation: opPing})
	return err
}

// noBody runs an operation whose request and response have headers only.
func (c *Client) noBody(ctx context.Context, request rpcRequest) (rpcResponse, error) {
	stream, err := c.open(ctx)
	if err != nil {
		return rpcResponse{}, err
	}
	defer stream.CancelRead(streamCanceled)
	if err = wire.WriteHeader(stream, request); err != nil {
		stream.CancelWrite(streamCanceled)
		return rpcResponse{}, unavailable(err)
	}
	if err = stream.Close(); err != nil {
		return rpcResponse{}, unavailable(err)
	}
	return readResponse(stream)
}

// open creates one operation stream and preserves a caller context error rather
// than obscuring it as transport unavailability.
func (c *Client) open(ctx context.Context) (*quic.Stream, error) {
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, unavailable(err)
	}
	return stream, nil
}

// readResponse decodes common version and typed-error semantics.
func readResponse(stream io.Reader) (rpcResponse, error) {
	var response rpcResponse
	if err := wire.ReadHeader(stream, &response); err != nil {
		return response, unavailable(err)
	}
	if response.Version != ProtocolVersion {
		return response, errorf(CodeUnavailable, "unsupported response protocol version %d", response.Version)
	}
	if !response.OK {
		if response.Error == nil {
			return response, errorf(CodeInternal, "remote operation failed without an error")
		}
		return response, response.Error
	}
	return response, nil
}

// RPCServer serves a provider ObjectStore over an established QUIC connection.
type RPCServer struct {
	// Store is the authoritative backend served to the peer.
	Store ObjectStore
	// Logger receives one structured operation/byte/duration line per handled
	// stream. A nil Logger disables operation logging.
	Logger interface{ Printf(string, ...any) }
}

// Serve accepts and handles streams on one established peer connection until
// ctx is canceled or the peer closes the connection. Concurrent streams are
// handled concurrently. Canceling ctx closes the connection so blocked body
// reads and writes are released before Serve returns.
func (s *RPCServer) Serve(ctx context.Context, conn *quic.Conn) error {
	if s.Store == nil || conn == nil {
		return errorf(CodeInvalidArgument, "RPC server requires a store and connection")
	}
	// QUIC stream reads don't inherit ctx cancellation. Closing the connection
	// ensures in-flight PUT/GET handlers unblock before the server waits for
	// them during provider shutdown.
	stopClose := context.AfterFunc(ctx, func() {
		_ = conn.CloseWithError(0, "RPC server context canceled")
	})
	defer stopClose()
	var handlers sync.WaitGroup
	defer handlers.Wait()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			select {
			case <-conn.Context().Done():
				return nil
			default:
				return err
			}
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			s.handleStream(ctx, stream)
		}()
	}
}

// handleStream owns one accepted stream from request header through response
// FIN/reset and emits the operation log after all transfer work completes.
func (s *RPCServer) handleStream(ctx context.Context, stream *quic.Stream) {
	start := time.Now()
	var request rpcRequest
	if err := wire.ReadHeader(stream, &request); err != nil {
		_ = writeRPCError(stream, errorf(CodeInvalidArgument, "malformed request header: %v", err))
		stream.CancelRead(streamCanceled)
		return
	}
	if request.Version != ProtocolVersion {
		_ = writeRPCError(stream, errorf(CodeInvalidArgument, "unsupported protocol version %d", request.Version))
		stream.CancelRead(streamCanceled)
		return
	}
	var bytesTransferred int64
	var err error
	switch request.Operation {
	case opPut:
		bytesTransferred, err = s.handlePut(ctx, stream, request)
	case opGet:
		bytesTransferred, err = s.handleGet(ctx, stream, request)
	case opHead:
		err = s.handleHead(ctx, stream, request)
	case opDelete:
		err = s.handleDelete(ctx, stream, request)
	case opList:
		bytesTransferred, err = s.handleList(ctx, stream, request)
	case opPing:
		err = wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true})
	default:
		err = writeRPCError(stream, errorf(CodeInvalidArgument, "unknown operation %q", request.Operation))
	}
	if err == nil {
		err = stream.Close()
	} else {
		stream.CancelWrite(streamCanceled)
	}
	if s.Logger != nil {
		s.Logger.Printf("operation=%s bucket=%q key=%q bytes=%d duration=%s error=%v", request.Operation, request.Bucket, request.Key, bytesTransferred, time.Since(start), err)
	}
}

// handlePut limits the readable body to its declaration before handing the
// stream to the storage implementation.
func (s *RPCServer) handlePut(ctx context.Context, stream *quic.Stream, request rpcRequest) (int64, error) {
	if request.BodySize < -1 {
		return 0, writeRPCError(stream, errorf(CodeInvalidArgument, "invalid PUT body size"))
	}
	var body io.Reader = stream
	if request.BodySize >= 0 {
		body = &declaredBodyReader{reader: stream, remaining: request.BodySize}
	}
	request.Put.Size = request.BodySize
	info, err := s.Store.Put(ctx, request.Bucket, request.Key, body, request.Put)
	if err != nil {
		stream.CancelRead(streamCanceled)
		return 0, writeRPCError(stream, err)
	}
	return info.Size, wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true, Object: &info})
}

// declaredBodyReader enforces an exact request boundary while leaving the QUIC
// stream available for the server's response direction.
type declaredBodyReader struct {
	reader    io.Reader
	remaining int64
	checked   bool
}

func (r *declaredBodyReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.reader.Read(p)
		r.remaining -= int64(n)
		if n > 0 && errors.Is(err, io.EOF) {
			err = nil
		}
		return n, err
	}
	if r.checked {
		return 0, io.EOF
	}
	r.checked = true
	// Probe once after the declared boundary. This distinguishes an exact body
	// followed by stream FIN from a sender that attempted to append extra bytes.
	var extra [1]byte
	n, err := r.reader.Read(extra[:])
	if n > 0 {
		return 0, errorf(CodeInvalidArgument, "PUT body exceeds declared size")
	}
	return 0, err
}

// handleGet writes metadata before streaming exactly the indexed object size.
func (s *RPCServer) handleGet(ctx context.Context, stream *quic.Stream, request rpcRequest) (int64, error) {
	info, body, err := s.Store.Get(ctx, request.Bucket, request.Key)
	if err != nil {
		return 0, writeRPCError(stream, err)
	}
	defer body.Close()
	if err = wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true, Object: &info, BodySize: info.Size}); err != nil {
		return 0, err
	}
	written, err := copyContext(ctx, stream, body)
	if err == nil && written != info.Size {
		err = fmt.Errorf("GET body size changed: wrote %d, expected %d", written, info.Size)
	}
	return written, err
}

// handleHead writes metadata without opening or copying an object body.
func (s *RPCServer) handleHead(ctx context.Context, stream *quic.Stream, request rpcRequest) error {
	info, err := s.Store.Head(ctx, request.Bucket, request.Key)
	if err != nil {
		return writeRPCError(stream, err)
	}
	return wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true, Object: &info})
}

// handleDelete returns an empty success response after idempotent deletion.
func (s *RPCServer) handleDelete(ctx context.Context, stream *quic.Stream, request rpcRequest) error {
	if err := s.Store.Delete(ctx, request.Bucket, request.Key); err != nil {
		return writeRPCError(stream, err)
	}
	return wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true})
}

// handleList materializes one bounded metadata page as the declared response
// body; object bytes are never involved.
func (s *RPCServer) handleList(ctx context.Context, stream *quic.Stream, request rpcRequest) (int64, error) {
	result, err := s.Store.List(ctx, request.Bucket, request.List)
	if err != nil {
		return 0, writeRPCError(stream, err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		return 0, writeRPCError(stream, err)
	}
	if err = wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: true, BodySize: int64(len(body))}); err != nil {
		return 0, err
	}
	n, err := stream.Write(body)
	return int64(n), err
}

// writeRPCError converts a local error to its safe wire representation.
func writeRPCError(stream io.Writer, err error) error {
	typed := normalizeError(err)
	return wire.WriteHeader(stream, rpcResponse{Version: ProtocolVersion, OK: false, Error: typed})
}

// copyContext copies through one reusable 64 KiB buffer and checks cancellation
// between reads, keeping memory independent of object size.
func copyContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 64*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, readErr := source.Read(buffer)
		if n > 0 {
			wn, writeErr := destination.Write(buffer[:n])
			written += int64(wn)
			if writeErr != nil {
				return written, writeErr
			}
			if wn != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

// unavailable classifies a local transport cause without discarding it.
func unavailable(err error) error {
	if err == nil {
		return nil
	}
	return &Error{Code: CodeUnavailable, Message: err.Error(), Err: err}
}

// remoteBody bounds a GET reader to the declared response size and coordinates
// EOF, Close, and context cancellation for one QUIC stream.
type remoteBody struct {
	stream    *quic.Stream
	remaining int64
	done      chan struct{}
	once      sync.Once
}

// newRemoteBody starts the lightweight context watcher for a streaming GET.
func newRemoteBody(ctx context.Context, stream *quic.Stream, size int64) *remoteBody {
	body := &remoteBody{stream: stream, remaining: size, done: make(chan struct{})}
	// QUIC reads don't directly observe arbitrary contexts. The watcher resets
	// this stream when the operation context is canceled and exits at EOF/Close.
	go func() {
		select {
		case <-ctx.Done():
			stream.CancelRead(streamCanceled)
		case <-body.done:
		}
	}()
	return body
}

func (b *remoteBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		b.finish(false)
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.stream.Read(p)
	b.remaining -= int64(n)
	if err != nil || b.remaining == 0 {
		b.finish(false)
	}
	if errors.Is(err, io.EOF) && b.remaining > 0 {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (b *remoteBody) Close() error {
	b.finish(b.remaining > 0)
	return nil
}

// finish stops the context watcher and optionally resets an unread stream.
func (b *remoteBody) finish(cancel bool) {
	b.once.Do(func() {
		if cancel {
			b.stream.CancelRead(streamCanceled)
		}
		close(b.done)
	})
}
