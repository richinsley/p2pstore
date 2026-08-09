package p2pstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// objectsBucket is versioned so a future on-disk schema can coexist with or be
// migrated explicitly from the v1 record layout.
var objectsBucket = []byte("objects-v1")

type FSConfig struct {
	// Directory is the provider root containing index.db, blobs, and tmp.
	Directory string
	// DefaultTTL applies when PutOptions specifies neither TTL nor ExpiresAt.
	// Zero disables default expiry.
	DefaultTTL time.Duration
	// MaxBytes limits the total size of committed and in-flight replacement
	// growth. Zero disables the quota.
	MaxBytes int64
	// JanitorInterval controls expiry and orphan cleanup. Zero defaults to one
	// minute.
	JanitorInterval time.Duration
}

// DefaultFSConfig returns a filesystem configuration rooted at directory with
// a one-minute janitor interval, no default expiry, and no byte quota.
func DefaultFSConfig(directory string) FSConfig {
	return FSConfig{
		Directory:       directory,
		JanitorInterval: time.Minute,
	}
}

// diskRecord is the complete indexed value. Blob is a random basename relative
// to FSStore.blobs, never a caller-controlled path.
type diskRecord struct {
	ObjectInfo
	Blob string `json:"blob"`
}

// FSStore is an authoritative filesystem provider backed by versioned blob
// files and a bbolt metadata index. Object content is never held in memory in
// its entirety.
//
// An FSStore is safe for concurrent use. Put and Delete operations for the same
// object are serialized; different keys can stream concurrently. Call Close
// when the provider shuts down to stop maintenance and close the index.
type FSStore struct {
	cfg   FSConfig
	db    *bolt.DB
	blobs string
	tmp   string
	stop  chan struct{}
	done  chan struct{}
	close sync.Once

	maintenance sync.RWMutex
	quotaMu     sync.Mutex
	used        int64
	reserved    int64
	keyMu       sync.Mutex
	keyLocks    map[string]*sync.Mutex
}

var _ ObjectStore = (*FSStore)(nil)

// OpenFS opens or creates an authoritative filesystem store.
//
// Startup removes expired index entries, unreferenced blob versions, and
// abandoned temporary PUT files before accepting operations. Only one process
// may open a given Directory at a time; bbolt lock acquisition waits for up to
// one second.
func OpenFS(cfg FSConfig) (*FSStore, error) {
	if cfg.Directory == "" {
		return nil, errorf(CodeInvalidArgument, "filesystem directory is empty")
	}
	if cfg.DefaultTTL < 0 || cfg.MaxBytes < 0 || cfg.JanitorInterval < 0 {
		return nil, errorf(CodeInvalidArgument, "TTL, quota, and janitor interval cannot be negative")
	}
	if cfg.JanitorInterval == 0 {
		cfg.JanitorInterval = time.Minute
	}
	blobs := filepath.Join(cfg.Directory, "blobs")
	tmp := filepath.Join(cfg.Directory, "tmp")
	if err := os.MkdirAll(blobs, 0o700); err != nil {
		return nil, fmt.Errorf("create blob directory: %w", err)
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("create temporary directory: %w", err)
	}
	db, err := bolt.Open(filepath.Join(cfg.Directory, "index.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open index: %w", err)
	}
	store := &FSStore{
		cfg: cfg, db: db, blobs: blobs, tmp: tmp,
		stop: make(chan struct{}), done: make(chan struct{}), keyLocks: make(map[string]*sync.Mutex),
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		_, createErr := tx.CreateBucketIfNotExists(objectsBucket)
		return createErr
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize index: %w", err)
	}
	if err = store.cleanup(time.Now()); err != nil {
		_ = db.Close()
		return nil, err
	}
	go store.janitor()
	return store, nil
}

// Close stops the expiry janitor and closes the bbolt index. It is idempotent.
func (s *FSStore) Close() error {
	var err error
	s.close.Do(func() {
		close(s.stop)
		<-s.done
		s.maintenance.Lock()
		defer s.maintenance.Unlock()
		err = s.db.Close()
	})
	return err
}

// Put streams body into a temporary file, verifies its declared size, computes
// its SHA-256 ETag, and atomically publishes a new indexed blob version. On
// cancellation or failure, the old version remains visible and temporary data
// is removed.
func (s *FSStore) Put(ctx context.Context, bucket, key string, body io.Reader, options PutOptions) (_ ObjectInfo, err error) {
	defer func() { err = typedStoreError(err) }()
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, err
	}
	if body == nil {
		return ObjectInfo{}, errorf(CodeInvalidArgument, "PUT body is nil")
	}
	if options.Size < -1 || options.TTL < 0 {
		return ObjectInfo{}, errorf(CodeInvalidArgument, "invalid PUT size or TTL")
	}
	unlock := s.lockKey(indexKey(bucket, key))
	defer unlock()
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()

	old, found, err := s.lookup(bucket, key, false)
	if err != nil {
		return ObjectInfo{}, err
	}
	oldSize := int64(0)
	if found {
		oldSize = old.Size
	}

	// Positive sizes can reserve quota once. Unknown-size streams reserve only
	// their net growth as data arrives, keeping concurrent PUTs within MaxBytes.
	declared := options.Size > 0
	reservation := int64(0)
	if declared {
		reservation = max64(0, options.Size-oldSize)
		if err = s.reserve(reservation); err != nil {
			return ObjectInfo{}, err
		}
	}
	committed := false
	defer func() {
		if !committed {
			s.releaseReservation(reservation)
		}
	}()

	tmpFile, err := os.CreateTemp(s.tmp, "put-*.tmp")
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("create temporary blob: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	closed := false
	defer func() {
		if !closed {
			_ = tmpFile.Close()
		}
	}()

	hash := sha256.New()
	buffer := make([]byte, 64*1024)
	var size int64
	for {
		if err = ctx.Err(); err != nil {
			return ObjectInfo{}, err
		}
		n, readErr := body.Read(buffer)
		if n > 0 {
			nextSize := size + int64(n)
			if declared && nextSize > options.Size {
				return ObjectInfo{}, errorf(CodeInvalidArgument, "PUT body exceeds declared size %d", options.Size)
			}
			if !declared {
				target := max64(0, nextSize-oldSize)
				if target > reservation {
					if err = s.reserve(target - reservation); err != nil {
						return ObjectInfo{}, err
					}
					reservation = target
				}
			}
			if _, err = tmpFile.Write(buffer[:n]); err != nil {
				return ObjectInfo{}, fmt.Errorf("write temporary blob: %w", err)
			}
			_, _ = hash.Write(buffer[:n])
			size = nextSize
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return ObjectInfo{}, readErr
			}
			break
		}
		if n == 0 {
			continue
		}
	}
	if declared && size != options.Size {
		return ObjectInfo{}, errorf(CodeInvalidArgument, "PUT body size %d does not match declared size %d", size, options.Size)
	}
	if err = ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	if err = tmpFile.Sync(); err != nil {
		return ObjectInfo{}, fmt.Errorf("sync temporary blob: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return ObjectInfo{}, fmt.Errorf("close temporary blob: %w", err)
	}
	closed = true

	blobName, err := randomBlobName()
	if err != nil {
		return ObjectInfo{}, err
	}
	blobPath := filepath.Join(s.blobs, blobName)
	// A blob becomes durable before the bbolt record points at it. A crash in
	// between can leave only an orphan, which OpenFS/cleanup safely removes.
	if err = os.Rename(tmpPath, blobPath); err != nil {
		return ObjectInfo{}, fmt.Errorf("commit blob file: %w", err)
	}
	if err = syncDirectory(s.blobs); err != nil {
		_ = os.Remove(blobPath)
		return ObjectInfo{}, fmt.Errorf("sync blob directory: %w", err)
	}
	removeBlob := true
	defer func() {
		if removeBlob {
			_ = os.Remove(blobPath)
		}
	}()

	now := time.Now().UTC()
	info := ObjectInfo{
		Bucket: bucket, Key: key, Size: size, ContentType: options.ContentType,
		ETag: hex.EncodeToString(hash.Sum(nil)), CreatedAt: now,
	}
	if options.ExpiresAt != nil {
		expires := options.ExpiresAt.UTC()
		if !expires.After(now) {
			return ObjectInfo{}, errorf(CodeInvalidArgument, "expiry must be in the future")
		}
		info.ExpiresAt = &expires
	} else {
		ttl := options.TTL
		if ttl == 0 {
			ttl = s.cfg.DefaultTTL
		}
		if ttl > 0 {
			expires := now.Add(ttl)
			info.ExpiresAt = &expires
		}
	}
	record := diskRecord{ObjectInfo: info, Blob: blobName}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ObjectInfo{}, err
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(objectsBucket).Put([]byte(indexKey(bucket, key)), encoded)
	}); err != nil {
		return ObjectInfo{}, fmt.Errorf("commit object index: %w", err)
	}
	removeBlob = false
	if found && old.Blob != "" && old.Blob != blobName {
		_ = os.Remove(filepath.Join(s.blobs, old.Blob))
	}
	s.quotaMu.Lock()
	s.used = s.used - oldSize + size
	s.reserved -= reservation
	s.quotaMu.Unlock()
	committed = true
	return info, nil
}

// Get opens the current unexpired blob for streaming. The returned reader
// checks ctx before each read and must be closed by the caller.
func (s *FSStore) Get(ctx context.Context, bucket, key string) (_ ObjectInfo, _ io.ReadCloser, err error) {
	defer func() { err = typedStoreError(err) }()
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, nil, err
	}
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	record, found, err := s.lookup(bucket, key, true)
	if err != nil {
		return ObjectInfo{}, nil, err
	}
	if !found {
		return ObjectInfo{}, nil, errorf(CodeNotFound, "%s/%s not found", bucket, key)
	}
	file, err := os.Open(filepath.Join(s.blobs, record.Blob))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ObjectInfo{}, nil, errorf(CodeInternal, "indexed blob is missing")
		}
		return ObjectInfo{}, nil, err
	}
	return record.ObjectInfo, &contextReadCloser{ctx: ctx, reader: file, closer: file}, nil
}

// Head returns metadata for the current unexpired object version.
func (s *FSStore) Head(ctx context.Context, bucket, key string) (_ ObjectInfo, err error) {
	defer func() { err = typedStoreError(err) }()
	if err := validateObject(bucket, key); err != nil {
		return ObjectInfo{}, err
	}
	if err := ctx.Err(); err != nil {
		return ObjectInfo{}, err
	}
	record, found, err := s.lookup(bucket, key, true)
	if err != nil {
		return ObjectInfo{}, err
	}
	if !found {
		return ObjectInfo{}, errorf(CodeNotFound, "%s/%s not found", bucket, key)
	}
	return record.ObjectInfo, nil
}

// Delete removes the indexed object version and then its blob. It succeeds when
// the object is absent, making retries safe.
func (s *FSStore) Delete(ctx context.Context, bucket, key string) (err error) {
	defer func() { err = typedStoreError(err) }()
	if err := validateObject(bucket, key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock := s.lockKey(indexKey(bucket, key))
	defer unlock()
	s.maintenance.RLock()
	defer s.maintenance.RUnlock()
	record, found, err := s.lookup(bucket, key, false)
	if err != nil || !found {
		return err // DELETE is idempotent.
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(objectsBucket).Delete([]byte(indexKey(bucket, key)))
	}); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(s.blobs, record.Blob))
	s.quotaMu.Lock()
	s.used -= record.Size
	s.quotaMu.Unlock()
	return nil
}

// List returns unexpired object metadata in lexical key order. Cursors bind to
// the bucket and prefix that created them and are rejected if reused elsewhere.
func (s *FSStore) List(ctx context.Context, bucket string, options ListOptions) (_ ListResult, err error) {
	defer func() { err = typedStoreError(err) }()
	if err := validateBucket(bucket); err != nil {
		return ListResult{}, err
	}
	options, err = normalizeListOptions(options)
	if err != nil {
		return ListResult{}, err
	}
	startAfter := ""
	if options.Cursor != "" {
		var cursor listCursor
		raw, decodeErr := base64.RawURLEncoding.DecodeString(options.Cursor)
		if decodeErr != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Bucket != bucket || cursor.Prefix != options.Prefix {
			return ListResult{}, errorf(CodeInvalidArgument, "invalid list cursor")
		}
		startAfter = cursor.Key
	}
	result := ListResult{Objects: make([]ObjectInfo, 0, options.Limit)}
	now := time.Now()
	err = s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(objectsBucket).Cursor()
		seek := []byte(indexKey(bucket, options.Prefix))
		for k, v := cursor.Seek(seek); k != nil; k, v = cursor.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			keyBucket, objectKey, ok := splitIndexKey(string(k))
			if !ok || keyBucket != bucket || !strings.HasPrefix(objectKey, options.Prefix) {
				break
			}
			if objectKey <= startAfter {
				continue
			}
			var record diskRecord
			if decodeErr := json.Unmarshal(v, &record); decodeErr != nil {
				return decodeErr
			}
			if expired(record.ObjectInfo, now) {
				continue
			}
			if len(result.Objects) == options.Limit {
				result.Truncated = true
				return nil
			}
			result.Objects = append(result.Objects, record.ObjectInfo)
		}
		return nil
	})
	if err != nil {
		return ListResult{}, err
	}
	if result.Truncated && len(result.Objects) > 0 {
		last := result.Objects[len(result.Objects)-1].Key
		raw, _ := json.Marshal(listCursor{Bucket: bucket, Prefix: options.Prefix, Key: last})
		result.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return result, nil
}

type listCursor struct {
	Bucket string `json:"b"`
	Prefix string `json:"p"`
	Key    string `json:"k"`
}

// lookup reads one index record. When hideExpired is true, expiry is enforced
// logically without mutating the index; the janitor reclaims it later.
func (s *FSStore) lookup(bucket, key string, hideExpired bool) (diskRecord, bool, error) {
	var record diskRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket(objectsBucket).Get([]byte(indexKey(bucket, key)))
		if value == nil {
			return nil
		}
		found = true
		return json.Unmarshal(value, &record)
	})
	if hideExpired && found && expired(record.ObjectInfo, time.Now()) {
		found = false
	}
	return record, found, err
}

// cleanup reconciles the index and blob directories at startup and on every
// janitor pass, then recomputes committed quota usage from surviving records.
func (s *FSStore) cleanup(now time.Time) error {
	// Maintenance excludes active filesystem operations while it reconciles the
	// index and directories. Expired records are deleted first, then any blob
	// not referenced by the surviving index is an orphan and can be removed.
	s.maintenance.Lock()
	defer s.maintenance.Unlock()
	referenced := make(map[string]struct{})
	var expiredBlobs []string
	var used int64
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(objectsBucket)
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var record diskRecord
			if err := json.Unmarshal(v, &record); err != nil {
				return err
			}
			if expired(record.ObjectInfo, now) {
				expiredBlobs = append(expiredBlobs, record.Blob)
				if err := cursor.Delete(); err != nil {
					return err
				}
				continue
			}
			referenced[record.Blob] = struct{}{}
			used += record.Size
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("clean index: %w", err)
	}
	for _, blob := range expiredBlobs {
		_ = os.Remove(filepath.Join(s.blobs, blob))
	}
	entries, err := os.ReadDir(s.blobs)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if _, ok := referenced[entry.Name()]; !ok {
			_ = os.Remove(filepath.Join(s.blobs, entry.Name()))
		}
	}
	tmpEntries, _ := os.ReadDir(s.tmp)
	for _, entry := range tmpEntries {
		if !entry.IsDir() {
			_ = os.Remove(filepath.Join(s.tmp, entry.Name()))
		}
	}
	s.quotaMu.Lock()
	s.used = used
	s.quotaMu.Unlock()
	return nil
}

// janitor runs cleanup until Close signals shutdown.
func (s *FSStore) janitor() {
	defer close(s.done)
	ticker := time.NewTicker(s.cfg.JanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.cleanup(time.Now())
		case <-s.stop:
			return
		}
	}
}

// reserve atomically accounts for in-flight object growth before bytes become
// durable, preventing concurrent PUTs from collectively exceeding MaxBytes.
func (s *FSStore) reserve(amount int64) error {
	if amount <= 0 {
		return nil
	}
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	if s.cfg.MaxBytes > 0 && s.used+s.reserved+amount > s.cfg.MaxBytes {
		return errorf(CodeQuotaExceeded, "storage quota of %d bytes exceeded", s.cfg.MaxBytes)
	}
	s.reserved += amount
	return nil
}

// releaseReservation returns quota held by a failed or canceled PUT.
func (s *FSStore) releaseReservation(amount int64) {
	if amount <= 0 {
		return
	}
	s.quotaMu.Lock()
	s.reserved -= amount
	s.quotaMu.Unlock()
}

// lockKey serializes index and blob mutation for one object. Locks remain in
// the small map for the store lifetime to avoid unsafe deletion races.
func (s *FSStore) lockKey(key string) func() {
	s.keyMu.Lock()
	lock := s.keyLocks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		s.keyLocks[key] = lock
	}
	s.keyMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

// validateObject applies both namespace validation rules.
func validateObject(bucket, key string) error {
	if err := validateBucket(bucket); err != nil {
		return err
	}
	return validateKey(key)
}

// indexKey produces a collision-free lexical bbolt key. NUL is unavailable in
// validated bucket names and object keys.
func indexKey(bucket, key string) string { return bucket + "\x00" + key }

// splitIndexKey reverses indexKey and rejects corrupt keys without a separator.
func splitIndexKey(value string) (string, string, bool) {
	index := strings.IndexByte(value, 0)
	if index < 0 {
		return "", "", false
	}
	return value[:index], value[index+1:], true
}

// randomBlobName generates an unguessable immutable blob basename.
func randomBlobName() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]) + ".blob", nil
}

// syncDirectory makes a successful blob rename durable on platforms that
// support syncing directory entries. Windows does not expose this operation.
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// expired treats the exact expiry instant as expired.
func expired(info ObjectInfo, now time.Time) bool {
	return info.ExpiresAt != nil && !now.Before(*info.ExpiresAt)
}

// contextReadCloser makes a local blob read observe its operation context while
// retaining explicit file ownership through Close.
type contextReadCloser struct {
	ctx    context.Context
	reader io.Reader
	closer io.Closer
}

func (r *contextReadCloser) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (r *contextReadCloser) Close() error { return r.closer.Close() }

// max64 returns the greater signed 64-bit value.
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
