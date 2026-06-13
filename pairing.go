package hap

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// PairingData is the long-term result of a successful pair-setup. It is everything
// needed to re-establish an encrypted session later via Verify, so it must be persisted
// securely: ControllerLTSK is a private key. Callers choose where to store it via
// Save/LoadPairingData.
type PairingData struct {
	// AccessoryID is the accessory's pairing identifier (its HAP device ID string).
	AccessoryID string `json:"accessory_id"`
	// AccessoryLTPK is the accessory's Ed25519 long-term public key (32 bytes).
	AccessoryLTPK []byte `json:"accessory_ltpk"`
	// ControllerID is the identifier we registered with the accessory (a UUID we generate).
	ControllerID string `json:"controller_id"`
	// ControllerLTSK is our Ed25519 private key seed (32 bytes); pairs with the public
	// key the accessory stored for us.
	ControllerLTSK []byte `json:"controller_ltsk"`
}

// valid reports whether the pairing data has all fields populated with plausible sizes.
func (p PairingData) valid() error {
	switch {
	case p.AccessoryID == "":
		return fmt.Errorf("hap: pairing data missing accessory ID")
	case len(p.AccessoryLTPK) != 32:
		return fmt.Errorf("hap: accessory LTPK is %d bytes, want 32", len(p.AccessoryLTPK))
	case p.ControllerID == "":
		return fmt.Errorf("hap: pairing data missing controller ID")
	case len(p.ControllerLTSK) != 32:
		return fmt.Errorf("hap: controller LTSK is %d bytes, want 32", len(p.ControllerLTSK))
	}
	return nil
}

// Save writes the pairing data as indented JSON.
func (p PairingData) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// SaveToFile is a convenience method to write the pairing data to a file.
func (p PairingData) SaveToFile(filename string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := p.Save(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPairingData reads pairing data previously written by Save.
func LoadPairingData(r io.Reader) (PairingData, error) {
	var p PairingData
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return PairingData{}, fmt.Errorf("hap: decoding pairing data: %w", err)
	}
	if err := p.valid(); err != nil {
		return PairingData{}, err
	}
	return p, nil
}

// LoadPairingDataFromFile is a convenience method to read pairing data from a file.
func LoadPairingDataFromFile(filename string) (PairingData, error) {
	f, err := os.Open(filename)
	if err != nil {
		return PairingData{}, err
	}
	defer f.Close()
	return LoadPairingData(f)
}
