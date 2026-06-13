package hap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeRequestWrite(t *testing.T) {
	got := encodeRequest(opCharWrite, 0x11, 0x004a, []byte{0xde, 0xad})
	want := []byte{
		controlRequest, opCharWrite, 0x11, // control, opcode, tid
		0x4a, 0x00, // iid, little-endian
		0x02, 0x00, // body length, little-endian
		0xde, 0xad,
	}
	assert.Equal(t, want, got)
}

// A read has no body, so the length field must be omitted entirely.
func TestEncodeRequestReadHasNoLength(t *testing.T) {
	got := encodeRequest(opCharRead, 0x05, 0x0010, nil)
	want := []byte{controlRequest, opCharRead, 0x05, 0x10, 0x00}
	assert.Equal(t, want, got)
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
	require.NoError(t, err)
	for i := 1; len(body) < bodyLen; i++ {
		more, err := continuationBody(frags[i])
		require.NoError(t, err)
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
	require.GreaterOrEqual(t, len(frags), 2, "expected multiple fragments")
	for _, f := range frags[1:] {
		assert.Equal(t, []byte{controlContinuation, 0x11}, f[:2], "continuation header mismatch")
	}

	status, got := reassemble(t, 0x11, frags)
	assert.Equal(t, byte(0), status)
	assert.Equal(t, body, got)
}

func TestParseFirstResponseTIDMismatch(t *testing.T) {
	resp := encodeResponse(0x22, 0x00, []byte{1, 2, 3})
	_, _, _, err := parseFirstResponse(0x11, resp)
	assert.Error(t, err)
}

func TestParseFirstResponseEmptyBody(t *testing.T) {
	resp := encodeResponse(0x11, 0x06, nil) // e.g. a non-zero status with no body
	status, bodyLen, body, err := parseFirstResponse(0x11, resp)
	require.NoError(t, err)
	assert.Equal(t, byte(0x06), status)
	assert.Zero(t, bodyLen)
	assert.Empty(t, body)
}
