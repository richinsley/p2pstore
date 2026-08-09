package p2pstore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T, mutate func(*FSConfig)) *FSStore {
	t.Helper()
	cfg := DefaultFSConfig(t.TempDir())
	if mutate != nil {
		mutate(&cfg)
	}
	store, err := OpenFS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestFSStoreCRUDOverwriteAndRestart(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenFS(DefaultFSConfig(directory))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	first, err := store.Put(ctx, "bucket", "a/key", strings.NewReader("first"), PutOptions{Size: 5, ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Size != 5 || len(first.ETag) != 64 {
		t.Fatalf("unexpected info: %+v", first)
	}
	second, err := store.Put(ctx, "bucket", "a/key", strings.NewReader("second"), PutOptions{Size: 6})
	if err != nil {
		t.Fatal(err)
	}
	if first.ETag == second.ETag {
		t.Fatal("overwrite retained old ETag")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFS(DefaultFSConfig(directory))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	info, body, err := store.Get(ctx, "bucket", "a/key")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil || string(data) != "second" || info.ETag != second.ETag {
		t.Fatalf("restart GET: data=%q info=%+v err=%v", data, info, err)
	}
	if err = store.Delete(ctx, "bucket", "a/key"); err != nil {
		t.Fatal(err)
	}
	if err = store.Delete(ctx, "bucket", "a/key"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
	_, err = store.Head(ctx, "bucket", "a/key")
	if !IsCode(err, CodeNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestFSStoreListPaginationIsLexical(t *testing.T) {
	store := newTestStore(t, nil)
	ctx := context.Background()
	for _, key := range []string{"prefix/c", "other", "prefix/a", "prefix/b"} {
		if _, err := store.Put(ctx, "bucket", key, bytes.NewBufferString(key), PutOptions{Size: int64(len(key))}); err != nil {
			t.Fatal(err)
		}
	}
	page1, err := store.List(ctx, "bucket", ListOptions{Prefix: "prefix/", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !page1.Truncated || page1.NextCursor == "" || gotKeys(page1) != "prefix/a,prefix/b" {
		t.Fatalf("page 1: %+v", page1)
	}
	page2, err := store.List(ctx, "bucket", ListOptions{Prefix: "prefix/", Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if page2.Truncated || gotKeys(page2) != "prefix/c" {
		t.Fatalf("page 2: %+v", page2)
	}
	_, err = store.List(ctx, "bucket", ListOptions{Prefix: "different", Cursor: page1.NextCursor})
	if !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("cursor should be bound to query: %v", err)
	}
}

func TestFSStoreTTLQuotaAndCancellation(t *testing.T) {
	store := newTestStore(t, func(cfg *FSConfig) {
		cfg.DefaultTTL = 30 * time.Millisecond
		cfg.MaxBytes = 8
		cfg.JanitorInterval = 10 * time.Millisecond
	})
	ctx := context.Background()
	if _, err := store.Put(ctx, "bucket", "ttl", strings.NewReader("1234"), PutOptions{Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, "bucket", "quota", strings.NewReader("12345"), PutOptions{Size: 5, TTL: time.Hour}); !IsCode(err, CodeQuotaExceeded) {
		t.Fatalf("expected quota error, got %v", err)
	}
	time.Sleep(45 * time.Millisecond)
	if _, err := store.Head(ctx, "bucket", "ttl"); !IsCode(err, CodeNotFound) {
		t.Fatalf("expired object should be absent: %v", err)
	}

	cancelCtx, cancel := context.WithCancel(ctx)
	reader := &cancelReader{cancel: cancel}
	if _, err := store.Put(cancelCtx, "bucket", "cancel", reader, PutOptions{Size: -1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if _, err := store.Head(ctx, "bucket", "cancel"); !IsCode(err, CodeNotFound) {
		t.Fatalf("cancelled PUT became visible: %v", err)
	}
	entries, err := os.ReadDir(store.tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files after cancel: entries=%d err=%v", len(entries), err)
	}
}

func TestFSStoreStartupRemovesOrphan(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenFS(DefaultFSConfig(directory))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(directory, "blobs", "orphan.blob")
	if err = os.WriteFile(orphan, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = OpenFS(DefaultFSConfig(directory))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = os.Stat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan still exists: %v", err)
	}
}

func TestObjectValidation(t *testing.T) {
	store := newTestStore(t, nil)
	for _, tc := range []struct{ bucket, key string }{
		{"", "key"}, {"bucket", ""}, {"bucket", "/absolute"}, {"bucket", "a/../b"},
		{"bucket", "a/./b"}, {"bucket", "nul\x00key"}, {"bucket", strings.Repeat("x", 1025)},
	} {
		_, err := store.Head(context.Background(), tc.bucket, tc.key)
		if !IsCode(err, CodeInvalidArgument) {
			t.Errorf("Head(%q, %q) = %v", tc.bucket, tc.key, err)
		}
	}
}

type cancelReader struct {
	cancel func()
	done   bool
}

func (r *cancelReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	copy(p, "partial")
	r.cancel()
	return len("partial"), nil
}

func gotKeys(result ListResult) string {
	keys := make([]string, len(result.Objects))
	for i := range result.Objects {
		keys[i] = result.Objects[i].Key
	}
	return strings.Join(keys, ",")
}
