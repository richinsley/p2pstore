package p2pstore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These acceptance tests are intentionally opt-in because they write 1.5 GiB
// of temporary data. They use generated readers, never object-sized buffers.
func TestLargeStreamingAcceptance(t *testing.T) {
	if os.Getenv("P2PSTORE_LARGE_TESTS") != "1" {
		t.Skip("set P2PSTORE_LARGE_TESTS=1 to run large transfer acceptance")
	}
	t.Run("one-gibibyte", func(t *testing.T) {
		store := newTestStore(t, nil)
		client, stop := directQUICPair(t, store)
		defer stop()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		stopMemory, peak := sampleHeap()
		const size = int64(1 << 30)
		info, err := client.Put(ctx, "acceptance", "one-gib", io.LimitReader(zeroReader{}, size), PutOptions{Size: size})
		if err != nil {
			t.Fatal(err)
		}
		_, body, err := client.Get(ctx, "acceptance", "one-gib")
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		read, err := io.Copy(hash, body)
		_ = body.Close()
		stopMemory()
		if err != nil || read != size || fmt.Sprintf("%x", hash.Sum(nil)) != info.ETag {
			t.Fatalf("size=%d etag=%x info=%s err=%v", read, hash.Sum(nil), info.ETag, err)
		}
		// Both endpoints share this test process, so the per-process ceiling is
		// twice the 64 MiB per-endpoint requirement.
		if delta := peak(); delta > 128<<20 {
			t.Fatalf("additional process heap %d exceeds aggregate endpoint ceiling", delta)
		}
	})

	t.Run("eight-concurrent", func(t *testing.T) {
		store := newTestStore(t, nil)
		client, stop := directQUICPair(t, store)
		defer stop()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		stopMemory, peak := sampleHeap()
		const size = int64(64 << 20)
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				key := fmt.Sprintf("parallel/%d", i)
				info, err := client.Put(ctx, "acceptance", key, io.LimitReader(zeroReader{}, size), PutOptions{Size: size})
				if err != nil {
					errs <- err
					return
				}
				_, body, err := client.Get(ctx, "acceptance", key)
				if err != nil {
					errs <- err
					return
				}
				hash := sha256.New()
				read, err := io.Copy(hash, body)
				_ = body.Close()
				if err != nil || read != size || fmt.Sprintf("%x", hash.Sum(nil)) != info.ETag {
					errs <- fmt.Errorf("stream %d corrupted: size=%d err=%v", i, read, err)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		stopMemory()
		for err := range errs {
			t.Error(err)
		}
		if delta := peak(); delta > 512<<20 {
			t.Fatalf("additional process heap %d exceeds aggregate endpoint ceiling", delta)
		}
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func sampleHeap() (func(), func() uint64) {
	var baseline runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&baseline)
	var maximum atomic.Uint64
	maximum.Store(baseline.HeapAlloc)
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				var current runtime.MemStats
				runtime.ReadMemStats(&current)
				for old := maximum.Load(); current.HeapAlloc > old && !maximum.CompareAndSwap(old, current.HeapAlloc); old = maximum.Load() {
				}
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	peak := func() uint64 {
		if value := maximum.Load(); value > baseline.HeapAlloc {
			return value - baseline.HeapAlloc
		}
		return 0
	}
	return stop, peak
}
