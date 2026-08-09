package p2pstore

import (
	"context"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxListLimit is the largest page accepted by ObjectStore.List. A zero limit
// selects this value as the default.
const MaxListLimit = 1000

var bucketPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// ObjectStore is the common streaming contract implemented by local providers
// and remote clients.
//
// Implementations must honor context cancellation, return typed *Error values
// for storage failures, and make Delete idempotent. Callers must close every
// body returned by Get, including when they stop reading before EOF.
type ObjectStore interface {
	// Put atomically creates or replaces bucket/key by consuming body. A failed
	// or canceled Put must not make a partial object visible.
	Put(context.Context, string, string, io.Reader, PutOptions) (ObjectInfo, error)
	// Get returns metadata and a streaming body for bucket/key. The caller owns
	// the returned body and must close it.
	Get(context.Context, string, string) (ObjectInfo, io.ReadCloser, error)
	// Head returns metadata without opening the object body.
	Head(context.Context, string, string) (ObjectInfo, error)
	// Delete removes bucket/key. Deleting an absent or expired object succeeds.
	Delete(context.Context, string, string) error
	// List returns one lexical page of unexpired objects in bucket.
	List(context.Context, string, ListOptions) (ListResult, error)
}

// ObjectInfo describes one immutable object version returned by an operation.
// ETag identifies the exact body bytes; it is not an S3 multipart ETag.
type ObjectInfo struct {
	// Bucket is the object's validated bucket name.
	Bucket string `json:"bucket"`
	// Key is the object's UTF-8 key within Bucket.
	Key string `json:"key"`
	// Size is the number of object body bytes.
	Size int64 `json:"size"`
	// ContentType is optional caller-supplied media type metadata.
	ContentType string `json:"content_type,omitempty"`
	// ETag is the lowercase hexadecimal SHA-256 digest of the body.
	ETag string `json:"etag"`
	// CreatedAt is when the current object version was committed.
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is nil for a non-expiring object. At or after this instant the
	// object behaves as not found, even before janitor cleanup removes its blob.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// PutOptions controls metadata, body-size validation, and expiry for Put.
type PutOptions struct {
	// ContentType records optional media type metadata without interpreting it.
	ContentType string `json:"content_type,omitempty"`
	// Size is the declared number of body bytes. A negative value means that
	// the size is unknown and the body ends at EOF or stream FIN. Zero is also
	// treated as an unknown size by the remote Client so empty and chunked HTTP
	// requests can use the same streaming path.
	Size int64 `json:"size"`
	// TTL expires the object this long after a successful commit. Zero selects
	// the provider's DefaultTTL.
	TTL time.Duration `json:"ttl,omitempty"`
	// ExpiresAt sets an absolute expiry and takes precedence over TTL. It must
	// be in the future when the object commits.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ListOptions selects a lexical page from one bucket.
type ListOptions struct {
	// Prefix includes only keys beginning with this UTF-8 string.
	Prefix string `json:"prefix,omitempty"`
	// Cursor is the opaque NextCursor returned by a prior List call made with
	// the same bucket and Prefix.
	Cursor string `json:"cursor,omitempty"`
	// Limit is the maximum number of objects returned. Zero defaults to 1,000;
	// values above MaxListLimit are rejected.
	Limit int `json:"limit,omitempty"`
}

// ListResult is one lexical page of object metadata.
type ListResult struct {
	// Objects contains at most the requested limit and is ordered by key.
	Objects []ObjectInfo `json:"objects"`
	// NextCursor resumes after the last returned key. It is present only when
	// Truncated is true and must be treated as opaque by callers.
	NextCursor string `json:"next_cursor,omitempty"`
	// Truncated reports that another page exists.
	Truncated bool `json:"truncated"`
}

// validateBucket applies the protocol's bounded ASCII bucket grammar.
func validateBucket(bucket string) error {
	if !bucketPattern.MatchString(bucket) {
		return errorf(CodeInvalidArgument, "bucket must be 1-63 ASCII letters, digits, '.', '_' or '-' and start with a letter or digit")
	}
	return nil
}

// validateKey rejects unsafe path spellings without otherwise normalizing the
// caller's UTF-8 object key.
func validateKey(key string) error {
	if key == "" {
		return errorf(CodeInvalidArgument, "key is empty")
	}
	if !utf8.ValidString(key) || len(key) > 1024 {
		return errorf(CodeInvalidArgument, "key must be valid UTF-8 and at most 1024 bytes")
	}
	if strings.ContainsRune(key, 0) {
		return errorf(CodeInvalidArgument, "key contains NUL")
	}
	if strings.HasPrefix(key, "/") || path.IsAbs(key) {
		return errorf(CodeInvalidArgument, "key must be relative")
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "." || segment == ".." {
			return errorf(CodeInvalidArgument, "key contains a forbidden path segment")
		}
	}
	return nil
}

// normalizeListOptions validates prefix and limit and applies the default page
// size. Cursor integrity is backend-specific because the backend encodes it.
func normalizeListOptions(options ListOptions) (ListOptions, error) {
	if !utf8.ValidString(options.Prefix) || len(options.Prefix) > 1024 || strings.ContainsRune(options.Prefix, 0) {
		return options, errorf(CodeInvalidArgument, "prefix must be valid UTF-8, contain no NUL, and be at most 1024 bytes")
	}
	if options.Limit < 0 || options.Limit > MaxListLimit {
		return options, errorf(CodeInvalidArgument, "list limit must be between 1 and %d", MaxListLimit)
	}
	if options.Limit == 0 {
		options.Limit = MaxListLimit
	}
	return options, nil
}
