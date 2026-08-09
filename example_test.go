package p2pstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/richinsley/p2pstore"
)

// ExampleFSStore demonstrates the same streaming ObjectStore calls used for a
// local provider and a remote p2pstore.Client.
func ExampleFSStore() {
	directory, err := os.MkdirTemp("", "p2pstore-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(directory)

	store, err := p2pstore.OpenFS(p2pstore.DefaultFSConfig(directory))
	if err != nil {
		panic(err)
	}
	defer store.Close()

	ctx := context.Background()
	payload := []byte("hello p2pstore")
	info, err := store.Put(
		ctx,
		"examples",
		"greeting.txt",
		bytes.NewReader(payload),
		p2pstore.PutOptions{Size: int64(len(payload)), ContentType: "text/plain"},
	)
	if err != nil {
		panic(err)
	}

	_, body, err := store.Get(ctx, info.Bucket, info.Key)
	if err != nil {
		panic(err)
	}
	defer body.Close()

	got, err := io.ReadAll(body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(got))
	fmt.Println(info.Size)

	// Output:
	// hello p2pstore
	// 14
}

// ExampleIsCode shows how callers branch on stable storage error codes while
// retaining ordinary errors.Is behavior for context cancellation.
func ExampleIsCode() {
	store, err := p2pstore.OpenFS(p2pstore.DefaultFSConfig(""))
	fmt.Println(store == nil)
	fmt.Println(p2pstore.IsCode(err, p2pstore.CodeInvalidArgument))
	fmt.Println(errors.Is(context.Canceled, context.Canceled))

	// Output:
	// true
	// true
	// true
}
