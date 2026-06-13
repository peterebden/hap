package hap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLVRoundTrip(t *testing.T) {
	in := tlvs{}.
		addByte(tlvState, 3).
		addByte(tlvMethod, 0).
		add(tlvIdentifier, []byte("hello")).
		add(tlvPublicKey, bytes.Repeat([]byte{0xab}, 32))

	out, err := decodeTLV(in.encode())
	require.NoError(t, err)

	state, ok := out.firstByte(tlvState)
	require.True(t, ok)
	assert.Equal(t, byte(3), state)

	id, ok := out.first(tlvIdentifier)
	require.True(t, ok)
	assert.Equal(t, "hello", string(id))

	pk, ok := out.first(tlvPublicKey)
	require.True(t, ok)
	assert.Equal(t, bytes.Repeat([]byte{0xab}, 32), pk)
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
	assert.Len(t, encoded, 600+3*2)
	assert.Equal(t, byte(tlvEncryptedData), encoded[0])
	assert.Equal(t, byte(255), encoded[1])

	out, err := decodeTLV(encoded)
	require.NoError(t, err)
	v, ok := out.first(tlvEncryptedData)
	require.True(t, ok)
	assert.Equal(t, long, v)
}

func TestTLVDecodeTruncated(t *testing.T) {
	// Length byte claims 5 bytes but only 2 follow.
	_, err := decodeTLV([]byte{tlvIdentifier, 5, 0x01, 0x02})
	assert.Error(t, err)
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
	require.NoError(t, err)

	var ids []string
	for _, item := range out {
		if item.Type == tlvIdentifier {
			ids = append(ids, string(item.Value))
		}
	}
	assert.Equal(t, []string{"aaa", "bbb"}, ids)
}
