// Package gateway exposes a deliberately small, unsigned, path-style S3
// compatibility surface for local applications and S3-compatible clients.
package gateway

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/richinsley/p2pstore"
)

// Handler translates the supported unsigned, path-style S3 requests to an
// ObjectStore. Store must remain valid for the lifetime of the handler.
type Handler struct {
	// Store receives all object operations issued through the HTTP facade.
	Store p2pstore.ObjectStore
}

// NewHandler validates store and returns an S3-compatible HTTP handler.
//
// The handler implements path-style PutObject, GetObject, HeadObject,
// DeleteObject, and ListObjectsV2 only. It deliberately provides no AWS
// authentication, bucket administration, multipart, range, or conditional
// request behavior and should normally be bound to loopback.
func NewHandler(store p2pstore.ObjectStore) (*Handler, error) {
	if store == nil {
		return nil, errors.New("p2pstore gateway: nil object store")
	}
	return &Handler{Store: store}, nil
}

// ServeHTTP dispatches one request from the supported S3 compatibility subset.
func (h *Handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	bucket, key, err := splitPath(request.URL.EscapedPath())
	if err != nil {
		writeError(w, request, err)
		return
	}
	if key == "" {
		if request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "2" {
			h.list(w, request, bucket)
			return
		}
		writeS3Error(w, "InvalidRequest", "unsupported bucket operation", "", http.StatusBadRequest, request.Method == http.MethodHead)
		return
	}
	switch request.Method {
	case http.MethodPut:
		h.put(w, request, bucket, key)
	case http.MethodGet:
		h.get(w, request, bucket, key)
	case http.MethodHead:
		h.head(w, request, bucket, key)
	case http.MethodDelete:
		h.delete(w, request, bucket, key)
	default:
		writeS3Error(w, "MethodNotAllowed", "method not allowed", key, http.StatusMethodNotAllowed, request.Method == http.MethodHead)
	}
}

// put streams the HTTP request body directly into the configured store.
func (h *Handler) put(w http.ResponseWriter, request *http.Request, bucket, key string) {
	size := request.ContentLength
	if size == 0 {
		size = -1
	}
	info, err := h.Store.Put(request.Context(), bucket, key, request.Body, p2pstore.PutOptions{
		ContentType: request.Header.Get("Content-Type"), Size: size,
	})
	if err != nil {
		writeError(w, request, err)
		return
	}
	w.Header().Set("ETag", quoteETag(info.ETag))
	w.WriteHeader(http.StatusOK)
}

// get streams a store body directly to the HTTP response.
func (h *Handler) get(w http.ResponseWriter, request *http.Request, bucket, key string) {
	info, body, err := h.Store.Get(request.Context(), bucket, key)
	if err != nil {
		writeError(w, request, err)
		return
	}
	defer body.Close()
	writeObjectHeaders(w, info)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, body)
}

// head translates object metadata into S3-compatible response headers.
func (h *Handler) head(w http.ResponseWriter, request *http.Request, bucket, key string) {
	info, err := h.Store.Head(request.Context(), bucket, key)
	if err != nil {
		writeError(w, request, err)
		return
	}
	writeObjectHeaders(w, info)
	w.WriteHeader(http.StatusOK)
}

// delete maps the store's idempotent DELETE to HTTP 204.
func (h *Handler) delete(w http.ResponseWriter, request *http.Request, bucket, key string) {
	if err := h.Store.Delete(request.Context(), bucket, key); err != nil {
		writeError(w, request, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// list implements the ListObjectsV2 query subset and XML response shape.
func (h *Handler) list(w http.ResponseWriter, request *http.Request, bucket string) {
	query := request.URL.Query()
	limit := 1000
	if raw := query.Get("max-keys"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 || parsed > p2pstore.MaxListLimit {
			writeS3Error(w, "InvalidArgument", "max-keys must be between 0 and 1000", "", http.StatusBadRequest, false)
			return
		}
		limit = parsed
		if limit == 0 {
			result := listBucketResult{XMLNS: s3Namespace, Name: bucket, Prefix: query.Get("prefix"), MaxKeys: 0, KeyCount: 0}
			writeXML(w, result)
			return
		}
	}
	result, err := h.Store.List(request.Context(), bucket, p2pstore.ListOptions{
		Prefix: query.Get("prefix"), Cursor: query.Get("continuation-token"), Limit: limit,
	})
	if err != nil {
		writeError(w, request, err)
		return
	}
	contents := make([]object, len(result.Objects))
	for i, info := range result.Objects {
		contents[i] = object{
			Key: info.Key, LastModified: info.CreatedAt.UTC().Format(time.RFC3339Nano),
			ETag: quoteETag(info.ETag), Size: info.Size, StorageClass: "STANDARD",
		}
	}
	writeXML(w, listBucketResult{
		XMLNS: s3Namespace, Name: bucket, Prefix: query.Get("prefix"),
		ContinuationToken: query.Get("continuation-token"), NextContinuationToken: result.NextCursor,
		KeyCount: len(contents), MaxKeys: limit, IsTruncated: result.Truncated, Contents: contents,
	})
}

// writeObjectHeaders maps shared object metadata to the supported S3 headers.
func writeObjectHeaders(w http.ResponseWriter, info p2pstore.ObjectInfo) {
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("ETag", quoteETag(info.ETag))
	w.Header().Set("Last-Modified", info.CreatedAt.UTC().Format(http.TimeFormat))
	if info.ContentType != "" {
		w.Header().Set("Content-Type", info.ContentType)
	}
}

// splitPath decodes a path-style /bucket/key URL without cleaning it, leaving
// traversal validation to p2pstore's object-key rules.
func splitPath(escaped string) (string, string, error) {
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return "", "", &p2pstore.Error{Code: p2pstore.CodeInvalidArgument, Message: "invalid escaped S3 path"}
	}
	trimmed := strings.TrimPrefix(decoded, "/")
	if trimmed == "" {
		return "", "", &p2pstore.Error{Code: p2pstore.CodeInvalidArgument, Message: "missing bucket"}
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 1 {
		return parts[0], "", nil
	}
	if parts[1] == "" {
		return parts[0], "", nil
	}
	return parts[0], parts[1], nil
}

const s3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	XMLNS                 string   `xml:"xmlns,attr"`
	Name                  string   `xml:"Name"`
	Prefix                string   `xml:"Prefix"`
	ContinuationToken     string   `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string   `xml:"NextContinuationToken,omitempty"`
	KeyCount              int      `xml:"KeyCount"`
	MaxKeys               int      `xml:"MaxKeys"`
	IsTruncated           bool     `xml:"IsTruncated"`
	Contents              []object `xml:"Contents"`
}

type object struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type errorResponse struct {
	XMLName  xml.Name `xml:"Error"`
	Code     string   `xml:"Code"`
	Message  string   `xml:"Message"`
	Resource string   `xml:"Resource,omitempty"`
}

// writeError translates stable p2pstore codes to the closest S3-style error.
func writeError(w http.ResponseWriter, request *http.Request, err error) {
	code, message, status := "InternalError", "internal storage failure", http.StatusInternalServerError
	switch {
	case p2pstore.IsCode(err, p2pstore.CodeInvalidArgument):
		code, message, status = "InvalidArgument", err.Error(), http.StatusBadRequest
	case p2pstore.IsCode(err, p2pstore.CodeNotFound):
		code, message, status = "NoSuchKey", "The specified key does not exist.", http.StatusNotFound
	case p2pstore.IsCode(err, p2pstore.CodeQuotaExceeded):
		code, message, status = "QuotaExceeded", err.Error(), http.StatusInsufficientStorage
	case p2pstore.IsCode(err, p2pstore.CodeUnavailable):
		code, message, status = "ServiceUnavailable", err.Error(), http.StatusServiceUnavailable
	case p2pstore.IsCode(err, p2pstore.CodeUnauthenticated):
		code, message, status = "AccessDenied", err.Error(), http.StatusForbidden
	}
	writeS3Error(w, code, message, request.URL.Path, status, request.Method == http.MethodHead)
}

// writeS3Error emits an XML S3 error, suppressing the body for HEAD requests.
func writeS3Error(w http.ResponseWriter, code, message, resource string, status int, head bool) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if head {
		return
	}
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errorResponse{Code: code, Message: message, Resource: resource})
}

// writeXML emits a successful XML response with the standard declaration.
func writeXML(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(value)
}

// quoteETag ensures S3's required quoted ETag representation exactly once.
func quoteETag(value string) string {
	return `"` + strings.Trim(value, `"`) + `"`
}

// Server owns a pre-bound TCP listener and the loopback S3 compatibility HTTP
// server using it.
type Server struct {
	listener net.Listener
	http     *http.Server
	addr     string
}

// NewServer binds addr immediately and returns a server ready for
// ListenAndServe. An empty addr defaults to 127.0.0.1:9800. Passing port zero is
// supported for tests and dynamic local allocation.
func NewServer(store p2pstore.ObjectStore, addr string) (*Server, error) {
	handler, err := NewHandler(store)
	if err != nil {
		return nil, err
	}
	if addr == "" {
		addr = "127.0.0.1:9800"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		listener: listener,
		http:     &http.Server{Addr: listener.Addr().String(), Handler: handler},
		addr:     listener.Addr().String(),
	}, nil
}

// ListenAndServe serves until Shutdown closes the listener. A normal shutdown
// returns nil.
func (s *Server) ListenAndServe() error {
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops HTTP handling and closes the bound listener.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	listenerErr := s.listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	return errors.Join(err, listenerErr)
}

// Addr returns the actual bound address, including a dynamically selected port.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.addr
}
