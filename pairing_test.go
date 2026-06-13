package hap

import (
	"bytes"
	"testing"
)

func TestPairingDataRoundTrip(t *testing.T) {
	in := PairingData{
		AccessoryID:    "AA:BB:CC:DD:EE:FF",
		AccessoryLTPK:  bytes.Repeat([]byte{0x01}, 32),
		ControllerID:   "5a3e6f12-0000-0000-0000-000000000000",
		ControllerLTSK: bytes.Repeat([]byte{0x02}, 32),
	}
	var buf bytes.Buffer
	if err := in.Save(&buf); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := LoadPairingData(&buf)
	if err != nil {
		t.Fatalf("LoadPairingData: %v", err)
	}
	if out.AccessoryID != in.AccessoryID || out.ControllerID != in.ControllerID ||
		!bytes.Equal(out.AccessoryLTPK, in.AccessoryLTPK) || !bytes.Equal(out.ControllerLTSK, in.ControllerLTSK) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestLoadPairingDataRejectsBadKey(t *testing.T) {
	// Valid JSON but the LTPK is the wrong length.
	bad := `{"accessory_id":"x","accessory_ltpk":"AQID","controller_id":"y","controller_ltsk":"AQID"}`
	if _, err := LoadPairingData(bytes.NewReader([]byte(bad))); err == nil {
		t.Error("expected error for short LTPK, got nil")
	}
}
