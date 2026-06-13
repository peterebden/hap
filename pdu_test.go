package hap

import (
	"bytes"
	"testing"
)

func TestEncodeRequestWrite(t *testing.T) {
	got := encodeRequest(opCharWrite, 0x11, 0x004a, []byte{0xde, 0xad})
	want := []byte{
		controlRequest, opCharWrite, 0x11, // control, opcode, tid
		0x4a, 0x00, // iid, little-endian
		0x02, 0x00, // body length, little-endian
		0xde, 0xad,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeRequest = % x; want % x", got, want)
	}
}

// A read has no body, so the length field must be omitted entirely.
func TestEncodeRequestReadHasNoLength(t *testing.T) {
	got := encodeRequest(opCharRead, 0x05, 0x0010, nil)
	want := []byte{controlRequest, opCharRead, 0x05, 0x10, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeRequest = % x; want % x", got, want)
	}
}

// encodeResponse mirrors what an accessory sends, for exercising the parse path.
func encodeResponse(tid, status byte, body []byte) []byte {
	buf := []byte{controlRequest, tid, status}
	if len(body) > 0 {
		buf = append(buf, byte(len(body)), byte(len(body)>>8))
		buf = append(buf, body...)
	}
	return buf
}

// reassemble drives the same fragment loop the transport will use.
func reassemble(t *testing.T, tid byte, frags [][]byte) (byte, []byte) {
	t.Helper()
	status, bodyLen, body, err := parseFirstResponse(tid, frags[0])
	if err != nil {
		t.Fatalf("parseFirstResponse: %v", err)
	}
	for i := 1; len(body) < bodyLen; i++ {
		more, err := continuationBody(frags[i])
		if err != nil {
			t.Fatalf("continuationBody: %v", err)
		}
		body = append(body, more...)
	}
	return status, body
}

func TestResponseFragmentRoundTrip(t *testing.T) {
	body := make([]byte, 600)
	for i := range body {
		body[i] = byte(i * 7)
	}
	resp := encodeResponse(0x11, 0x00, body)

	frags := fragment(resp, 0x11, 20)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	for _, f := range frags[1:] {
		if f[0] != controlContinuation || f[1] != 0x11 {
			t.Errorf("continuation header = % x; want 80 11", f[:2])
		}
	}

	status, got := reassemble(t, 0x11, frags)
	if status != 0 {
		t.Errorf("status = %d; want 0", status)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("reassembled body mismatch (got %d bytes)", len(got))
	}
}

func TestParseFirstResponseTIDMismatch(t *testing.T) {
	resp := encodeResponse(0x22, 0x00, []byte{1, 2, 3})
	if _, _, _, err := parseFirstResponse(0x11, resp); err == nil {
		t.Error("expected transaction-ID mismatch error, got nil")
	}
}

func TestParseFirstResponseEmptyBody(t *testing.T) {
	resp := encodeResponse(0x11, 0x06, nil) // e.g. a non-zero status with no body
	status, bodyLen, body, err := parseFirstResponse(0x11, resp)
	if err != nil {
		t.Fatalf("parseFirstResponse: %v", err)
	}
	if status != 0x06 || bodyLen != 0 || len(body) != 0 {
		t.Errorf("got status %d, bodyLen %d, body %d bytes; want 6, 0, 0", status, bodyLen, len(body))
	}
}
