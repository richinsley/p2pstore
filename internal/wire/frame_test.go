package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := struct {
		Operation string `json:"operation"`
		Size      int64  `json:"size"`
	}{"PUT", 123}
	var frame bytes.Buffer
	if err := WriteHeader(&frame, want); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Operation string `json:"operation"`
		Size      int64  `json:"size"`
	}
	if err := ReadHeader(&frame, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestFrameRejectsOversizeBeforeAllocation(t *testing.T) {
	var frame bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], MaxHeaderSize+1)
	frame.Write(length[:])
	var got any
	if err := ReadHeader(&frame, &got); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func FuzzReadHeader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value any
		_ = ReadHeader(bytes.NewReader(data), &value)
	})
}
