package hap

import (
	"bytes"
	"testing"
)

func TestTLVRoundTrip(t *testing.T) {
	in := tlvs{}.
		addByte(tlvState, 3).
		addByte(tlvMethod, 0).
		add(tlvIdentifier, []byte("hello")).
		add(tlvPublicKey, bytes.Repeat([]byte{0xab}, 32))

	out, err := decodeTLV(in.encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if state, ok := out.firstByte(tlvState); !ok || state != 3 {
		t.Errorf("State = %d, %v; want 3, true", state, ok)
	}
	if id, ok := out.first(tlvIdentifier); !ok || string(id) != "hello" {
		t.Errorf("Identifier = %q, %v; want \"hello\", true", id, ok)
	}
	if pk, ok := out.first(tlvPublicKey); !ok || !bytes.Equal(pk, bytes.Repeat([]byte{0xab}, 32)) {
		t.Errorf("PublicKey mismatch")
	}
}

// A value longer than 255 bytes must be split into consecutive same-type chunks on
// encode and concatenated back on decode.
func TestTLVFragmentation(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = byte(i)
	}
	encoded := tlvs{}.add(tlvEncryptedData, long).encode()

	// Expect three on-wire items: 255 + 255 + 90, each with a length prefix.
	if want := 600 + 3*2; len(encoded) != want {
		t.Fatalf("encoded length = %d; want %d", len(encoded), want)
	}
	if encoded[0] != tlvEncryptedData || encoded[1] != 255 {
		t.Errorf("first chunk header = %x %d; want %x 255", encoded[0], encoded[1], tlvEncryptedData)
	}

	out, err := decodeTLV(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := out.first(tlvEncryptedData); !ok || !bytes.Equal(v, long) {
		t.Errorf("reassembled value mismatch (len %d, ok %v)", len(v), ok)
	}
}

func TestTLVDecodeTruncated(t *testing.T) {
	// Length byte claims 5 bytes but only 2 follow.
	if _, err := decodeTLV([]byte{tlvIdentifier, 5, 0x01, 0x02}); err == nil {
		t.Error("expected error on truncated TLV, got nil")
	}
}

// Distinct same-typed values separated by a zero-length separator must decode as two
// items, not one concatenated blob.
func TestTLVSeparatorKeepsValuesDistinct(t *testing.T) {
	encoded := tlvs{}.
		add(tlvIdentifier, []byte("aaa")).
		addByte(tlvSeparator, 0).
		add(tlvIdentifier, []byte("bbb")).
		encode()
	out, err := decodeTLV(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var ids [][]byte
	for _, item := range out {
		if item.Type == tlvIdentifier {
			ids = append(ids, item.Value)
		}
	}
	if len(ids) != 2 || string(ids[0]) != "aaa" || string(ids[1]) != "bbb" {
		t.Errorf("got %q; want two items aaa, bbb", ids)
	}
}
