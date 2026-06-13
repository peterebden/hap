package hap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPairingDataRoundTrip(t *testing.T) {
	in := PairingData{
		AccessoryID:    "AA:BB:CC:DD:EE:FF",
		AccessoryLTPK:  bytes.Repeat([]byte{0x01}, 32),
		ControllerID:   "5a3e6f12-0000-0000-0000-000000000000",
		ControllerLTSK: bytes.Repeat([]byte{0x02}, 32),
	}
	var buf bytes.Buffer
	require.NoError(t, in.Save(&buf))

	out, err := LoadPairingData(&buf)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestLoadPairingDataRejectsBadKey(t *testing.T) {
	// Valid JSON but the LTPK is the wrong length.
	bad := `{"accessory_id":"x","accessory_ltpk":"AQID","controller_id":"y","controller_ltsk":"AQID"}`
	_, err := LoadPairingData(bytes.NewReader([]byte(bad)))
	assert.Error(t, err)
}
