package gateway

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/richinsley/p2pstore"
)

func testHandler(t *testing.T) (*Handler, *p2pstore.FSStore) {
	t.Helper()
	store, err := p2pstore.OpenFS(p2pstore.DefaultFSConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler, err := NewHandler(store)
	if err != nil {
		t.Fatal(err)
	}
	return handler, store
}

func TestS3CRUDAndPagination(t *testing.T) {
	handler, _ := testHandler(t)
	for _, item := range []struct{ key, value string }{{"c", "three"}, {"a", "one"}, {"b", "two"}} {
		request := httptest.NewRequest(http.MethodPut, "/bucket/prefix/"+item.key, bytes.NewBufferString(item.value))
		request.Header.Set("Content-Type", "text/plain")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("ETag") == "" {
			t.Fatalf("PUT %s: status=%d body=%s", item.key, response.Code, response.Body.String())
		}
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/bucket/prefix/a", nil))
	if get.Code != http.StatusOK || get.Body.String() != "one" || get.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("GET: status=%d headers=%v body=%q", get.Code, get.Header(), get.Body.String())
	}
	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/bucket/prefix/a", nil))
	if head.Code != http.StatusOK || head.Header().Get("Content-Length") != "3" || head.Body.Len() != 0 {
		t.Fatalf("HEAD: status=%d headers=%v body=%q", head.Code, head.Header(), head.Body.String())
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/bucket?list-type=2&prefix=prefix/&max-keys=2", nil))
	var page1 listBucketResult
	if err := xml.Unmarshal(first.Body.Bytes(), &page1); err != nil {
		t.Fatal(err)
	}
	if first.Code != http.StatusOK || !page1.IsTruncated || page1.KeyCount != 2 || page1.Contents[0].Key != "prefix/a" {
		t.Fatalf("page 1: %+v body=%s", page1, first.Body.String())
	}
	second := httptest.NewRecorder()
	path := "/bucket?list-type=2&prefix=prefix/&max-keys=2&continuation-token=" + page1.NextContinuationToken
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, path, nil))
	var page2 listBucketResult
	if err := xml.Unmarshal(second.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if page2.IsTruncated || page2.KeyCount != 1 || page2.Contents[0].Key != "prefix/c" {
		t.Fatalf("page 2: %+v", page2)
	}

	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/bucket/prefix/a", nil))
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("DELETE status=%d", deleted.Code)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/bucket/prefix/a", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing GET status=%d", missing.Code)
	}
	data, _ := io.ReadAll(missing.Result().Body)
	var s3err errorResponse
	if err := xml.Unmarshal(data, &s3err); err != nil || s3err.Code != "NoSuchKey" {
		t.Fatalf("S3 error=%+v decode=%v", s3err, err)
	}
}

func TestS3RejectsTraversalAndOversizeLimit(t *testing.T) {
	handler, _ := testHandler(t)
	for _, target := range []string{"/bucket/a/../b", "/bucket/a/./b", "/bucket?list-type=2&max-keys=1001"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusBadRequest && response.Code != http.StatusNotFound {
			t.Errorf("%s: status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}
